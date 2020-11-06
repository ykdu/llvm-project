#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

// TODO: in python script: send/receive path
// TODO: return ealy
// TODO: function blacklist
// TODO: void * and void*
using namespace clang;
using namespace ento;

namespace {
    const unsigned Undef = 0;
    const unsigned WithLen = 1;
    const unsigned WithoutLen = 2;

    // To prune branches before '__rpc__', all visited '__rpc__' AST nodes are preserved.
    std::set<const Expr*> VisitedRPC;

    // To check redefined RPC, all visited RPC names are preserved.
    std::set<StringRef> VisitedRPCName;

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

    class DumpPathChecker : public Checker <check::PreCall, check::EndFunction> {
        mutable std::unique_ptr<BugType> BT_MISS_RPC;
        mutable std::unique_ptr<BugType> BT_MISS_END;
        mutable std::unique_ptr<BugType> BT_NESTED_RPC;
        mutable std::unique_ptr<BugType> BT_REDEFINED_RPC;
        mutable std::unique_ptr<BugType> BT_UNEXPECTED_SEND_LENGTH;
        mutable std::unique_ptr<BugType> BT_MISS_SEND_LENGTH;

        typedef void (DumpPathChecker::*FnCheck)(const CallEvent &Call, CheckerContext &C) const;
        CallDescriptionMap<FnCheck> RPCCallbacks = {
            {{"__instrumentation_4_static_analyzer_rpc", 2}, &DumpPathChecker::Entrance},
            {{"__instrumentation_4_static_analyzer", 2}, &DumpPathChecker::Step},
            {{"__instrumentation_4_static_analyzer_send_X", 2}, &DumpPathChecker::StepSendX},
            {{"__instrumentation_4_static_analyzer_send_X_length", 2}, &DumpPathChecker::StepSendXLength},
            {{"__instrumentation_4_static_analyzer_end", 2}, &DumpPathChecker::Exit},
        };

        void Entrance(const CallEvent &Call, CheckerContext &C) const;
        void Step(const CallEvent &Call, CheckerContext &C) const;
        void StepSendX(const CallEvent &Call, CheckerContext &C) const;
        void StepSendXLength(const CallEvent &Call, CheckerContext &C) const;
        void Exit(const CallEvent &Call, CheckerContext &C) const;

        // Report bug and set a sink node.
        void reportBug(std::unique_ptr<BugType> &BT, CheckerContext &C) const;
        void reportBug_MISS_RPC(CheckerContext &C) const;
        void reportBug_MISS_END(CheckerContext &C) const;
        void reportBug_NESTED_RPC(CheckerContext &C) const;
        void reportBug_REDEFINED_RPC(CheckerContext &C) const;
        void reportBug_UNEXPECTED_SEND_LENGTH(CheckerContext &C) const;
        void reportBug_MISS_SEND_LENGTH(CheckerContext &C) const;

        StringWrapper getStringFromExpr(const Expr *expr) const;
        void dumpPath(CheckerContext &C) const;
        void cleanup(CheckerContext &C) const;

        unsigned getSendLengthCnt(const Expr *expr, CheckerContext &C) const;
        ProgramStateRef incSendLengthCnt(const Expr *expr, CheckerContext &C) const;
        ProgramStateRef decSendLengthCnt(const Expr *expr, CheckerContext &C) const;

        public:
        void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
        void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
    };

}

// Maintain an call-stmt list
REGISTER_LIST_WITH_PROGRAMSTATE(CallList, const Expr*)

// Whether rpc_send_X_length is necessary in each rpc block
REGISTER_TRAIT_WITH_PROGRAMSTATE (NeedSendLength, unsigned)

// Paired send_X/send_X_length
REGISTER_MAP_WITH_PROGRAMSTATE(PreviousSendLength, StringWrapper, unsigned)

StringWrapper DumpPathChecker::getStringFromExpr(const Expr *expr) const {
    return StringWrapper(dyn_cast<StringLiteral>(expr->IgnoreParenCasts())->getString());
}

void DumpPathChecker::checkPreCall(const CallEvent &Call , CheckerContext &C) const {
    // Speedup the analysis: pruning calls
    if(Call.isGlobalCFunction() || C.wasInlined) {
        return;
    }

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
    // If we've already reached this node on another path, prune.
    if(VisitedRPC.find(expr) != VisitedRPC.end()) {
        C.addSink();
        return;
    }

    auto RPCName = getStringFromExpr(expr).get();
    // Illegal: Redefined RPC
    if(VisitedRPCName.find(RPCName) != VisitedRPCName.end()) {
        reportBug_REDEFINED_RPC(C);
        return;
    }

    VisitedRPC.insert(expr);
    VisitedRPCName.insert(RPCName);

    state = state->add<CallList>(expr);
    C.addTransition(state);
}

void DumpPathChecker::StepSendX(const CallEvent &Call , CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    const Expr* expr = Call.getArgExpr(0);

    // Illegal: Missing __rpc__
    if(state->get<CallList>().isEmpty()) {
        reportBug_MISS_RPC(C);
        return;
    }

    auto lstate = state->get<NeedSendLength>();
    if(lstate == WithLen) {
        auto old_state = state;
        state = decSendLengthCnt(expr, C);
        if(old_state==state) {
            return;
        }
    }
    if(lstate == Undef) {
        state = state->set<NeedSendLength>(WithoutLen);
    }

    state = state->add<CallList>(expr);
    C.addTransition(state);
}

void DumpPathChecker::StepSendXLength(const CallEvent &Call , CheckerContext &C) const {
    ProgramStateRef state = C.getState();

    // Illegal: Missing __rpc__
    if(state->get<CallList>().isEmpty()) {
        reportBug_MISS_RPC(C);
        return;
    }

    const Expr* expr = Call.getArgExpr(0);
    state = incSendLengthCnt(expr, C);

    auto lstate = state->get<NeedSendLength>();
    if(lstate == Undef) {
        state = state->set<NeedSendLength>(WithLen);
    }
    else if(lstate==WithoutLen) {
        reportBug_UNEXPECTED_SEND_LENGTH(C);
        return;
    }

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

void DumpPathChecker::reportBug_REDEFINED_RPC(CheckerContext &C) const {
    if(!BT_REDEFINED_RPC)
        BT_REDEFINED_RPC.reset(new BugType(this, "Redefined RPC", "Redefined RPC"));
    reportBug(BT_REDEFINED_RPC, C);
}

void DumpPathChecker::reportBug_UNEXPECTED_SEND_LENGTH(CheckerContext &C) const {
    if(!BT_UNEXPECTED_SEND_LENGTH)
        BT_UNEXPECTED_SEND_LENGTH.reset(new BugType(this, "Unexpected rpc_send_X_length", "Send Length"));
    reportBug(BT_UNEXPECTED_SEND_LENGTH, C);
}

void DumpPathChecker::reportBug_MISS_SEND_LENGTH(CheckerContext &C) const {
    if(!BT_MISS_SEND_LENGTH)
        BT_MISS_SEND_LENGTH.reset(new BugType(this, "Miss rpc_send_X_length", "Send Length"));
    reportBug(BT_MISS_SEND_LENGTH, C);
}

void DumpPathChecker::reportBug(std::unique_ptr<BugType> &BT, CheckerContext &C) const {
    ExplodedNode *N = C.generateErrorNode();
    if (!N)
        return;
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, BT->getDescription(), N);
    C.emitReport(std::move(Report));
}


/************************** Utils for send_X_length Checker *****************************/

unsigned DumpPathChecker::getSendLengthCnt(const Expr *expr, CheckerContext &C) const {
    auto signature = getStringFromExpr(expr);
    if (const unsigned *cnt = C.getState()->get<PreviousSendLength>(signature)) {
        return *cnt;
    }
    return 0;
}

/*
 * Increase the cnt of expr
 *
 * Return: A new state if succeed, or the origin state
 */
ProgramStateRef DumpPathChecker::incSendLengthCnt(const Expr *expr, CheckerContext &C) const {
    auto signature = getStringFromExpr(expr);
    auto state = C.getState()->set<PreviousSendLength>(signature, getSendLengthCnt(expr, C) + 1);
    return state;
}

/*
 * Try to decrease the cnt of expr
 *
 * Return: A new state if succeed, or the origin state
 */
ProgramStateRef DumpPathChecker::decSendLengthCnt(const Expr *expr, CheckerContext &C) const {
    auto state = C.getState();
    auto signature = getStringFromExpr(expr);
    unsigned cnt = getSendLengthCnt(expr, C);

    if(cnt == 0) {
        reportBug_MISS_SEND_LENGTH(C);
        return state;
    }
    return state->set<PreviousSendLength>(signature, cnt - 1);
}

/*END********************** Utils for send_X_length Checker *****************************/

void DumpPathChecker::cleanup(CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    state = state->remove<CallList>();
    C.addTransition(state);
}

void DumpPathChecker::dumpPath(CheckerContext &C) const {
    ProgramStateRef state = C.getState();

    llvm::outs() << "__end__\n";
    for (const auto &I : state->get<CallList>()) {
        llvm::outs() << "  " << getStringFromExpr(I).get() << "\n";
    }
    llvm::outs() << "__rpc__\n\n";
}


void ento::registerDumpPathChecker(CheckerManager &Mgr) {
    Mgr.registerChecker<DumpPathChecker>();
}

bool ento::shouldRegisterDumpPathChecker(const CheckerManager &mgr) {
    return true;
}
