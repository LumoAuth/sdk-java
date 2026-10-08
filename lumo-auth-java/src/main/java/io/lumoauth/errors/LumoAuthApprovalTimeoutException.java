package io.lumoauth.errors;

import io.lumoauth.model.ApprovalResult;

/**
 * A push approval expired, or the wait deadline passed, before anyone responded.
 * {@link #approval()} is the last observed state.
 */
public class LumoAuthApprovalTimeoutException extends LumoAuthException {

    private final transient ApprovalResult approval;

    public LumoAuthApprovalTimeoutException(ApprovalResult approval) {
        super(ErrorCodes.APPROVAL_TIMEOUT, "approval timed out before the user responded", null);
        this.approval = approval;
    }

    public ApprovalResult approval() {
        return approval;
    }
}
