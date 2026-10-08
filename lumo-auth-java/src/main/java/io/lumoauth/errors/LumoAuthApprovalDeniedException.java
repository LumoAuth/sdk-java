package io.lumoauth.errors;

import io.lumoauth.model.ApprovalResult;

/** A human explicitly denied a push approval. {@link #approval()} is the final payload, for audit. */
public class LumoAuthApprovalDeniedException extends LumoAuthException {

    private final transient ApprovalResult approval;

    public LumoAuthApprovalDeniedException(ApprovalResult approval) {
        super(ErrorCodes.APPROVAL_DENIED, "approval was denied", null);
        this.approval = approval;
    }

    public ApprovalResult approval() {
        return approval;
    }
}
