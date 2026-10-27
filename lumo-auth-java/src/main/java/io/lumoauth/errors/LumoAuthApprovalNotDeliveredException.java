package io.lumoauth.errors;

/**
 * The approval prompt reached no device, so nobody can approve the action in this call.
 *
 * <p>{@link #reason()} says why:
 * <ul>
 *   <li>{@link #REASON_EMAIL_FALLBACK_SENT}: LumoAuth answered 202. The user has no enrolled push device,
 *       or the user does not exist (LumoAuth gives the same answer for both). LumoAuth emailed a plain
 *       notice that has no approval link. There is no approval token to poll.</li>
 *   <li>{@link #REASON_NO_ENROLLED_DEVICE}: LumoAuth answered 428. The user has no enrolled device and
 *       the email notice could not be sent.</li>
 * </ul>
 * Never treat this exception as an approval. Ask the user to enrol the LumoAuth app, then try again.
 */
public class LumoAuthApprovalNotDeliveredException extends LumoAuthException {

    public static final String REASON_EMAIL_FALLBACK_SENT = "email_fallback_sent";
    public static final String REASON_NO_ENROLLED_DEVICE = "no_enrolled_device";

    private final String reason;
    private final String taskId;

    public LumoAuthApprovalNotDeliveredException(String reason, String taskId, String message) {
        this(reason, taskId, message, null);
    }

    public LumoAuthApprovalNotDeliveredException(String reason, String taskId, String message, Throwable cause) {
        super(ErrorCodes.APPROVAL_NOT_DELIVERED, message == null || message.isBlank()
            ? "the approval prompt reached no device (" + reason + ")" : message, cause);
        this.reason = reason;
        this.taskId = taskId;
    }

    /** {@link #REASON_EMAIL_FALLBACK_SENT} or {@link #REASON_NO_ENROLLED_DEVICE}. */
    public String reason() {
        return reason;
    }

    /** The task ID from the response body, or null when the body has none. */
    public String taskId() {
        return taskId;
    }
}
