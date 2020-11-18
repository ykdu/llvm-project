//===-- RPCChecker.cpp -----------------------------------------*- C++ -*-==//
//
// Defines a checker for proper use of Orion's RPC APIs.
//
// This checker could find bugs cross compilation units - disabled by default,
// enabled with
//   - `-analyzer-config core.RPC:loadPathLocation="/tmp/csa"'
//   - `-analyzer-config core.RPC:SavePathLocation="/tmp/csa"'
//   - `-analyzer-config core.RPC:SavePathMode="trunc"'
//
// On the way features:
//   - RPC whitelist.
//
//===----------------------------------------------------------------------===//
//
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <fstream>
#include <regex>

using namespace clang;
using namespace ento;

namespace {
    /* Wrapper of string.
     * Since we cannot directly put an llvm::StringRef into an immutable container.
     * */
    class StringWrapper {
        const llvm::StringRef Str;

        public:
        StringWrapper(const llvm::StringRef &S) : Str(S) {}
        const llvm::StringRef &get() const {return Str;}
        void Profile(llvm::FoldingSetNodeID &ID) const {ID.AddString(Str);}
        bool operator ==(const StringWrapper &RHS) const {return Str.str() == RHS.Str.str();}
        bool operator <(const StringWrapper &RHS) const {return Str.str() < RHS.Str.str();}
    };

    static StringWrapper getStringWrapper(const Expr *expr) {
        return StringWrapper(dyn_cast<StringLiteral>(expr->IgnoreParenCasts())->getString());
    }
}


namespace {
    /* DFA, to present whether rpc_send_X_length is nessisary.
     *
     * States: Undef; WithLen; WithoutLen; Bug
     * Symbols: send_length and send_X_length
     * State transition diagram:
     *
     *       -----(send_X_length)------> WithLen
     *      /                    ^            |
     * Undef                     |-------------
     *      \
     *       -----(send_length)--------> WithoutLen ----(send_X_length)---->Bug----|
     *                           ^                |                          ^     |
     *                           |--(send_length)--                          |------
     * */
    struct SendLengthDFA {
        static const unsigned Undef = 0;
        static const unsigned WithLen = 1; // must contain send_X_length
        static const unsigned WithoutLen = 2; // must not contain send_X_length
        static const unsigned Bug = 3;

        static unsigned dealSendX(const unsigned currentState) {
            switch(currentState) {
                case Undef: return WithoutLen;
                case WithLen: return WithLen;
                case WithoutLen: return WithoutLen;
                default: return Bug;
            }
        }

        static unsigned dealSendXLength(const unsigned currentState) {
            switch(currentState) {
                case Undef: return WithLen;
                case WithLen: return WithLen;
                case WithoutLen: return Bug;
                default: return Bug;
            }
        }
    };
}

// Whether rpc_send_X_length is necessary in each rpc block
REGISTER_TRAIT_WITH_PROGRAMSTATE (NeedSendLength, unsigned)

// Paired send_X/send_X_length
REGISTER_MAP_WITH_PROGRAMSTATE(PreviousSendLength, StringWrapper, unsigned)

// Maintain an rpc-stmt list
REGISTER_LIST_WITH_PROGRAMSTATE(Path, const Expr*)

namespace {
    /* Cross compilation unit checker handle
     * */
    class CrossCompilationUnit {
        const std::string pathDelimiter = "^";
        const std::string nameDelimiter = ":";
        bool loaded = false;
        std::map<std::string, std::set<std::string>> clientPathes ;
        std::map<std::string, std::set<std::string>> serverPathes;

        public:
        StringRef loadLocation;
        StringRef saveLocation;

        // Whether need load previous unit's pathes
        bool whetherLoad();

        // Whether need save my pathes
        bool whetherSave();

        // Add a path to clientPathes/serverPathes dictory
        // e.g., addPath("client:testA", "send;send_variable;receive;")
        void addPath(std::string name, const std::string pathStr);

        // Add a path to clientPathes/serverPathes dictory
        void addPath(PathTy listPath);

        // Load and deserialize pathes into clientPathes and serverPathes
        void deserialize();

        // Serialize and save clientPathes and serverPathes to file
        void serialize();

        // Find inconsistency bugs between two corss unit
        void crossUnitCheck(std::map<const Expr*, bool> visitedRPC);

        // (For debug)
        void dump();
    };


    class RPCChecker : public Checker <check::PreCall> {
        // All visited '__rpc__' AST nodes are preserved. true means rpc has been visited and been closed, false means visited but not closed.
        // 1. To prune branches before '__rpc__'.
        // 2. To check redefined RPC.
        mutable std::map<const Expr*, bool> _visitedRPC;

        // Bug types
        mutable std::unique_ptr<BugType> BT_MISSING_RPC;
        mutable std::unique_ptr<BugType> BT_NESTED_RPC;
        mutable std::unique_ptr<BugType> BT_REDEFINED_RPC;
        mutable std::unique_ptr<BugType> BT_UNEXPECTED_SEND_LENGTH;
        mutable std::unique_ptr<BugType> BT_MISSING_SEND_LENGTH;

        typedef void (RPCChecker::*FnCheck)(const CallEvent &Call, CheckerContext &C) const;
        CallDescriptionMap<FnCheck> RPCCallbacks = {
            {{"__instrumentation_4_static_analyzer_rpc", 2}, &RPCChecker::entrance},
            {{"__instrumentation_4_static_analyzer", 2}, &RPCChecker::step},
            {{"__instrumentation_4_static_analyzer_send_X", 2}, &RPCChecker::stepSendX},
            {{"__instrumentation_4_static_analyzer_send_X_length", 2}, &RPCChecker::stepSendXLength},
            {{"__instrumentation_4_static_analyzer_end", 2}, &RPCChecker::exit},
        };

        void entrance(const CallEvent &Call, CheckerContext &C) const;
        void step(const CallEvent &Call, CheckerContext &C) const;
        void stepSendX(const CallEvent &Call, CheckerContext &C) const;
        void stepSendXLength(const CallEvent &Call, CheckerContext &C) const;
        void exit(const CallEvent &Call, CheckerContext &C) const;

        // Report bug and set a sink node.
        void reportBug(std::unique_ptr<BugType> &BT, CheckerContext &C) const;
        void reportBug_MISSING_RPC(CheckerContext &C) const;
        void reportBug_NESTED_RPC(CheckerContext &C) const;
        void reportBug_UNEXPECTED_SEND_LENGTH(CheckerContext &C) const;
        void reportBug_MISSING_SEND_LENGTH(CheckerContext &C) const;

        /********************* Utils for send_X_length Checker ******************/
        unsigned getSendLengthCnt(const Expr *expr, CheckerContext &C) const;

        // Increase the cnt of expr
        // Return: A new state if succeed, or the origin state
        ProgramStateRef incSendLengthCnt(const Expr *expr, CheckerContext &C) const;

        // Try to decrease the cnt of expr
        // Return: A new state if succeed, or the origin state
        ProgramStateRef decSendLengthCnt(const Expr *expr, CheckerContext &C) const;

        public:
        mutable CrossCompilationUnit ccu;
        void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
        ~RPCChecker();
    };
}


bool CrossCompilationUnit::whetherLoad() {
    return loadLocation != "none";
}

bool CrossCompilationUnit::whetherSave() {
    return saveLocation != "none";
}

void CrossCompilationUnit::addPath(std::string name, const std::string pathStr) {
    // format pathStr, to unify the same semantic with different writing styles, e.g., void * and void*.
    std::string str = std::regex_replace(pathStr, std::regex("\\s*\\*\\s*"), "*");

    auto pos = name.find(nameDelimiter);
    std::string cs = name.substr(0, pos);
    name.erase(0, pos + nameDelimiter.length());

    auto &pathes = cs == "client" ? clientPathes: serverPathes;
    auto iter = pathes.find(name);
    if(iter == pathes.end()) {
        std::set<std::string> pathSet = {str};
        pathes.insert({name, pathSet});
    }
    else {
        iter->second.insert(str);
    }
}

void CrossCompilationUnit::addPath(PathTy listPath) {
    std::vector<std::string> vectorPath;
    for(const auto &I : listPath) {
        vectorPath.push_back(getStringWrapper(I).get().str());
    }
    auto name = vectorPath.back();
    vectorPath.pop_back();

    std::string pathStr;
    for(const auto &I : vectorPath) {
        pathStr += I + ";";
    }
    addPath(name, pathStr);
}

void CrossCompilationUnit::deserialize() {
    std::string line;
    std::ifstream fs(loadLocation.str());
    while (getline (fs, line)) {
        auto pos = line.find(pathDelimiter);
        std::string name = line.substr(0, pos);
        line.erase(0, pos + pathDelimiter.length());
        addPath(name, line);
    }
    fs.close();
    loaded = true;
}

void CrossCompilationUnit::serialize() {
    std::ofstream fs(saveLocation.str(), std::ios_base::out | std::ios_base::app);
    for(auto const& I: clientPathes) {
        auto &name = I.first;
        auto &pathSet = I.second;
        for(auto const& pathStr : pathSet) {
            fs << "client" << nameDelimiter << name << pathDelimiter << pathStr << "\n";
        }
    }

    for(auto const& I: serverPathes) {
        auto &name = I.first;
        auto &pathSet = I.second;
        for(auto const& pathStr : pathSet) {
            fs << "server" << nameDelimiter << name << pathDelimiter << pathStr << "\n";
        }
    }
    fs.close();
}

void CrossCompilationUnit::crossUnitCheck(std::map<const Expr*, bool> visitedRPC) {
    for(const auto &I: visitedRPC) {
        auto name = getStringWrapper(I.first).get().str();
        auto pos = name.find(nameDelimiter);
        name.erase(0, pos + nameDelimiter.length());

        auto iter = clientPathes.find(name);
        if(iter == clientPathes.end()) {
            // Unused server RPC, not a bug, just continue.
            continue;
        }
        auto clientSet = iter->second;

        iter = serverPathes.find(name);
        if(iter == serverPathes.end()) {
            llvm::errs() << "warning: Undefined RPC, not found in server. [core.RPC]\n    " << name << "\n";
            continue;
        }
        auto serverSet = iter->second;

        std::set<std::string> clientOnly;
        std::set_difference(clientSet.begin(), clientSet.end(), serverSet.begin(), serverSet.end(),
                    std::inserter(clientOnly, clientOnly.end()));
        for(const auto &path: clientOnly) {
            llvm::errs() << "warning: Unique client path, has no corresponding path in server. [core.RPC]\n    " \
                << name << "'s path ---> " << path << "\n";
        }

        std::set<std::string> serverOnly;
        std::set_difference(serverSet.begin(), serverSet.end(), clientSet.begin(), clientSet.end(),
                    std::inserter(serverOnly, serverOnly.begin()));
        for(const auto &path: serverOnly) {
            llvm::errs() << "warning: Unique server path, has no corresponding path in client. [core.RPC]\n    " \
                << name << "'s path ---> " << path << "\n";
        }
    }
}

void CrossCompilationUnit::dump() {
    for(auto const& I: clientPathes) {
        auto &name = I.first;
        auto &pathSet = I.second;
        for(auto const& pathStr : pathSet) {
            llvm::outs() << "client" << nameDelimiter << name << pathDelimiter << pathStr << "\n";
        }
    }
    for(auto const& I: serverPathes) {
        auto &name = I.first;
        auto &pathSet = I.second;
        for(auto const& pathStr : pathSet) {
            llvm::outs() << "server" << nameDelimiter << name << pathDelimiter << pathStr << "\n";
        }
    }
}


RPCChecker::~RPCChecker() {
    // Illegal: Missing __end__
    for(const auto &I: _visitedRPC) {
        if(!I.second) {
            auto name = getStringWrapper(I.first).get().str();
            llvm::errs() << "warning: Missing __end__ [core.RPC]\n    " << name << "\n";
        }
    }

    if(ccu.whetherSave()) {
        ccu.serialize();
    }

    if(ccu.whetherLoad()) {
        ccu.deserialize();
        ccu.crossUnitCheck(_visitedRPC);
    }
}

void RPCChecker::checkPreCall(const CallEvent &Call , CheckerContext &C) const {
    // Speedup the analysis: pruning calls
    if(Call.isGlobalCFunction() || C.wasInlined) {
        return;
    }

    if(const FnCheck *Callback = RPCCallbacks.lookup(Call)) {
        (this->**Callback)(Call, C);
    }
}

void RPCChecker::entrance(const CallEvent &Call , CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    const Expr *expr = Call.getArgExpr(0);

    // Illegal: Nested __rpc__
    if(!state->get<Path>().isEmpty()) {
        reportBug_NESTED_RPC(C);
        return;
    }

    // Speedup the analysis: pruning pathes
    // If we've already reached this node on another path, prune.
    if(_visitedRPC.find(expr) != _visitedRPC.end()) {
        C.addSink();
        return;
    }

    _visitedRPC[expr] = false;

    state = state->add<Path>(expr);
    C.addTransition(state);
}

void RPCChecker::stepSendX(const CallEvent &Call , CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    const Expr* expr = Call.getArgExpr(0);

    // Illegal: Missing __rpc__
    if(state->get<Path>().isEmpty()) {
        reportBug_MISSING_RPC(C);
        return;
    }

    // Updata the SendLength list
    auto lstate = SendLengthDFA::dealSendX(state->get<NeedSendLength>());
    if(lstate == SendLengthDFA::WithLen) {
        auto old_state = state;
        state = decSendLengthCnt(expr, C);
        if(old_state==state) {
            return;
        }
    }

    // Update the SendLength DFA
    state = state->set<NeedSendLength>(lstate);
    auto explored = C.addTransition(state);

    state = state->add<Path>(expr);
    C.addTransition(state, explored);
}

void RPCChecker::stepSendXLength(const CallEvent &Call , CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    const Expr* expr = Call.getArgExpr(0);

    // Illegal: Missing __rpc__
    if(state->get<Path>().isEmpty()) {
        reportBug_MISSING_RPC(C);
        return;
    }

    // Update the SendLength List
    state = incSendLengthCnt(expr, C);

    // Update the SendLength DFA
    auto lstate = SendLengthDFA::dealSendXLength(state->get<NeedSendLength>());
    state = state->set<NeedSendLength>(lstate);

    // Illegal: Unexpected rpc_send_X_length
    if(lstate == SendLengthDFA::Bug) {
        reportBug_UNEXPECTED_SEND_LENGTH(C);
        return;
    }

    C.addTransition(state);
}

void RPCChecker::step(const CallEvent &Call , CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    const Expr* expr = Call.getArgExpr(0);

    // Illegal: Missing __rpc__
    if(state->get<Path>().isEmpty()) {
        reportBug_MISSING_RPC(C);
        return;
    }

    state = state->add<Path>(expr);
    C.addTransition(state);
}

void RPCChecker::exit(const CallEvent &Call , CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    PathTy listPath = state->get<Path>();

    // Illegal rule: Missing __rpc__
    if(listPath.isEmpty()) {
        reportBug_MISSING_RPC(C);
        return;
    }

    // Pathes are stored into memory if necissary
    if(ccu.whetherSave() || ccu.whetherLoad()) {
        ccu.addPath(listPath);
    }

    const Expr *expr; // get corresponding __rpc__ node
    for(const auto &I : listPath) {
        expr = I;
    }

    _visitedRPC[expr] = true; // __end__ flag

    state = state->remove<Path>();
    C.addTransition(state);
}

void RPCChecker::reportBug_MISSING_RPC(CheckerContext &C) const {
    if(!BT_MISSING_RPC)
        BT_MISSING_RPC.reset(new BugType(this, "Missing __rpc__", "Unpaired __rpc__ and __end__"));
    reportBug(BT_MISSING_RPC, C);
}

void RPCChecker::reportBug_NESTED_RPC(CheckerContext &C) const {
    if(!BT_NESTED_RPC)
        BT_NESTED_RPC.reset(new BugType(this, "Nested RPC", "Unpaired __rpc__ and __end__"));
    reportBug(BT_NESTED_RPC, C);
}

void RPCChecker::reportBug_UNEXPECTED_SEND_LENGTH(CheckerContext &C) const {
    if(!BT_UNEXPECTED_SEND_LENGTH)
        BT_UNEXPECTED_SEND_LENGTH.reset(new BugType(this, "Unexpected rpc_send_X_length", "Send Length"));
    reportBug(BT_UNEXPECTED_SEND_LENGTH, C);
}

void RPCChecker::reportBug_MISSING_SEND_LENGTH(CheckerContext &C) const {
    if(!BT_MISSING_SEND_LENGTH)
        BT_MISSING_SEND_LENGTH.reset(new BugType(this, "Missing rpc_send_X_length", "Send Length"));
    reportBug(BT_MISSING_SEND_LENGTH, C);
}

void RPCChecker::reportBug(std::unique_ptr<BugType> &BT, CheckerContext &C) const {
    ExplodedNode *N = C.generateErrorNode();
    if (!N)
        return;
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, BT->getDescription(), N);
    C.emitReport(std::move(Report));

    // Error pathes should not participate in other check rules.
    const Expr *expr; // get corresponding __rpc__ node
    for(const auto &I : C.getState()->get<Path>()) {
        expr = I;
    }
    _visitedRPC.erase(expr);
}


unsigned RPCChecker::getSendLengthCnt(const Expr *expr, CheckerContext &C) const {
    auto signature = getStringWrapper(expr);
    if (const unsigned *cnt = C.getState()->get<PreviousSendLength>(signature)) {
        return *cnt;
    }
    return 0;
}

ProgramStateRef RPCChecker::incSendLengthCnt(const Expr *expr, CheckerContext &C) const {
    auto signature = getStringWrapper(expr);
    auto state = C.getState()->set<PreviousSendLength>(signature, getSendLengthCnt(expr, C) + 1);
    return state;
}

ProgramStateRef RPCChecker::decSendLengthCnt(const Expr *expr, CheckerContext &C) const {
    auto state = C.getState();
    auto signature = getStringWrapper(expr);
    unsigned cnt = getSendLengthCnt(expr, C);

    if(cnt == 0) {
        reportBug_MISSING_SEND_LENGTH(C);
        return state;
    }
    return state->set<PreviousSendLength>(signature, cnt - 1);
}


void ento::registerRPCChecker(CheckerManager &Mgr) {
    auto Chk = Mgr.registerChecker<RPCChecker>();
    Chk->ccu.loadLocation = Mgr.getAnalyzerOptions().getCheckerStringOption(Chk, "LoadPathLocation");

    auto mode = Mgr.getAnalyzerOptions().getCheckerStringOption(Chk, "SavePathMode");
    if(mode != "app" && mode != "trunc") {
        Mgr.reportInvalidCheckerOptionValue(Chk, "SavePathMode", "\"app\" or \"trunc\"");
    }

    Chk->ccu.saveLocation = Mgr.getAnalyzerOptions().getCheckerStringOption(Chk, "SavePathLocation");
    if(Chk->ccu.whetherSave()) {
        if(mode == "trunc") { // clear the save file
            std::fstream fs(Chk->ccu.saveLocation.str(), std::ios_base::out | std::ios_base::trunc);
            fs.close();
        }
    }

    if(Chk->ccu.loadLocation != "none" && Chk->ccu.saveLocation != "none") {
        Mgr.reportInvalidCheckerOptionValue(Chk, "SavePathLocation", 
                "cannot set both loadPathLocation and SavePathLocation");
    }
}

bool ento::shouldRegisterRPCChecker(const CheckerManager &mgr) {
    return true;
}
