package burp.extension.ui;

/**
 * Callback interface used by the scan orchestrator to ask the user whether
 * an intrusive test should be run.
 *
 * Implementations show a Swing dialog (on the Event-Dispatch Thread) and
 * block until the user responds.
 */
@FunctionalInterface
public interface IntrusiveApprovalCallback {

    /**
     * Called before an intrusive test is about to run.
     *
     * @param testCase the TestCase that is about to execute
     * @return APPROVE  – run this test
     *         SKIP     – skip this specific test, continue with others
     *         SKIP_ALL – skip this and all remaining intrusive tests
     */
    Decision ask(TestCase testCase);

    enum Decision { APPROVE, SKIP, SKIP_ALL }
}
