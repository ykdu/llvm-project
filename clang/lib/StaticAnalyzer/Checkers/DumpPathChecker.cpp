#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

// TODO: Warning when same __rpc__ name appears
// TODO: in python script: send/receive path
using namespace clang;
using namespace ento;

namespace {
    // To prune branches before '__rpc__', all visited '__rpc__' AST nodes are preserved.
    std::vector<const Expr*> VisitedRPC;

    class DumpPathChecker : public Checker <check::PreCall, check::EndFunction> {
        mutable std::unique_ptr<BugType> BT_MISS_RPC;
        mutable std::unique_ptr<BugType> BT_MISS_END;
        mutable std::unique_ptr<BugType> BT_NESTED_RPC;

        typedef void (DumpPathChecker::*FnCheck)(const CallEvent &Call, CheckerContext &C) const;
        CallDescriptionMap<FnCheck> RPCCallbacks = {
            {{"__instrumentation_4_static_analyzer_rpc", 2}, &DumpPathChecker::Entrance},
            {{"__instrumentation_4_static_analyzer", 2}, &DumpPathChecker::Step},
            {{"__instrumentation_4_static_analyzer_end", 2}, &DumpPathChecker::Exit},
        };

        void Entrance(const CallEvent &Call, CheckerContext &C) const;
        void Step(const CallEvent &Call, CheckerContext &C) const;
        void Exit(const CallEvent &Call, CheckerContext &C) const;

        // Report bug and set a sink node.
        void reportBug(std::unique_ptr<BugType> &BT, CheckerContext &C) const;
        void reportBug_MISS_RPC(CheckerContext &C) const;
        void reportBug_MISS_END(CheckerContext &C) const;
        void reportBug_NESTED_RPC(CheckerContext &C) const;

        void dumpExpr(const Expr* expr) const;
        void dumpPath(CheckerContext &C) const;
        void cleanup(CheckerContext &C) const;



        public:
        void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
        void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
    };

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
}

// Maintain an call-stmt list
REGISTER_LIST_WITH_PROGRAMSTATE(CallList, const Expr*);

void DumpPathChecker::checkPreCall(const CallEvent &Call , CheckerContext &C) const {
    // Speedup the analysis: pruning calls
    //if(!Call.isGlobalCFunction() || C.wasInlined)
        //return;

    if(const FnCheck *Callback = RPCCallbacks.lookup(Call)) {
        (this->**Callback)(Call, C);
    }
}

void DumpPathChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
    if (!C.inTopFrame()) {
        return;
    }

    ProgramStateRef state = C.getState();

    // Illegal: Missing __end__
    if(!state->get<CallList>().isEmpty()) {
        reportBug_MISS_END(C);
        return;
    }
}

void DumpPathChecker::Entrance(const CallEvent &Call , CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    const Expr *expr = Call.getArgExpr(0);

    // Illegal: Nested __rpc__
    if(!state->get<CallList>().isEmpty()) {
        reportBug_NESTED_RPC(C);
        return;
    }

    // Speedup the analysis: pruning pathes
    // If we've already reached this node on another path, return.
    if(!VisitedRPC.empty() && VisitedRPC.back() == expr) {
        C.addSink();
        return;
    }
    else {
        VisitedRPC.push_back(expr);
    }

    state = state->add<CallList>(expr);
    C.addTransition(state);
}

void DumpPathChecker::Step(const CallEvent &Call , CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    const Expr* expr = Call.getArgExpr(0);

    // Illegal: Missing __rpc__
    if(state->get<CallList>().isEmpty()) {
        reportBug_MISS_RPC(C);
        return;
    }

    state = state->add<CallList>(expr);
    C.addTransition(state);
}

void DumpPathChecker::Exit(const CallEvent &Call , CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    const Expr *expr = Call.getArgExpr(0);

    // Illegal rule: Missing __rpc__
    if(state->get<CallList>().isEmpty()) {
        reportBug_MISS_RPC(C);
        return;
    }

    dumpPath(C);
    cleanup(C);
}







void DumpPathChecker::reportBug_MISS_RPC(CheckerContext &C) const {
    if(!BT_MISS_RPC)
        BT_MISS_RPC.reset(new BugType(this, "Missing __rpc__", "Unpaired __rpc__ and __end__"));
    reportBug(BT_MISS_RPC, C);
}

void DumpPathChecker::reportBug_MISS_END(CheckerContext &C) const {
    if(!BT_MISS_END)
        BT_MISS_END.reset(new BugType(this, "Missing __end__", "Unpaired __rpc__ and __end__"));
    reportBug(BT_MISS_END, C);
}

void DumpPathChecker::reportBug_NESTED_RPC(CheckerContext &C) const {
    if(!BT_NESTED_RPC)
        BT_NESTED_RPC.reset(new BugType(this, "Nested RPC", "Unpaired __rpc__ and __end__"));
    reportBug(BT_NESTED_RPC, C);
}

void DumpPathChecker::reportBug(std::unique_ptr<BugType> &BT, CheckerContext &C) const {
    ExplodedNode *N = C.generateErrorNode();
    if (!N)
        return;
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, BT->getDescription(), N);
    C.emitReport(std::move(Report));
}

void DumpPathChecker::cleanup(CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    state = state->remove<CallList>();
    C.addTransition(state);
}

void DumpPathChecker::dumpPath(CheckerContext &C) const {
    ProgramStateRef state = C.getState();

    llvm::outs() << "__end__\n";
    for (const auto &I : state->get<CallList>()) {
        llvm::outs() << "  " << dyn_cast<StringLiteral>(I->IgnoreParenCasts())->getString().str() << "\n";
    }
    llvm::outs() << "__rpc__\n\n";
}

void DumpPathChecker::dumpExpr(const Expr *expr) const {
    llvm::outs() << dyn_cast<StringLiteral>(expr->IgnoreParenCasts())->getString().str() << "\n";
}


void ento::registerDumpPathChecker(CheckerManager &Mgr) {
    Mgr.registerChecker<DumpPathChecker>();
}

bool ento::shouldRegisterDumpPathChecker(const CheckerManager &mgr) {
    return true;
}
