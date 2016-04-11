import re
from array import array

# Burp includes
from burp import IBurpExtender
from burp import IScannerCheck
from burp import IProxyListener

# Custom imports
from BurpExtensionBoilerplate.lib.Issues import StdScanIssue

"""
Implement BurpExtender to inherit from multiple base classes
IBurpExtender is the base class required for all extensions

You can keep adding new Interfaces afer IScannerCheck and IProxyListener
if you want to add more extended functionality. Because Python.

Loaded interfaces:
    IScannerCheck - Custom scanner issues based on response regex matching
    IProxyListener - Highlights all POST requests in the Proxy HTTP history
    IIntruder -
"""


class BurpExtender(IBurpExtender, IScannerCheck, IProxyListener):

    """
    The only method of the IBurpExtender interface.
    This method is invoked when the extension is loaded and registers
    an instance of the IBurpExtenderCallbacks interface
    """

    def registerExtenderCallbacks(self, callbacks):
        # Putting callbacks in local var for accessibility (class level scope)
        self._callbacks = callbacks

        # Useful variables
        self._helpers = callbacks.getHelpers()

        # Setting the extion name
        self._callbacks.setExtensionName("Burp Extension Boilerplate")

        # Registering our functionality
        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerProxyListener(self)

        return

    """
    Standard Burp function that is called when multiple issues are reported
    for the same URL
    """

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0

    """
    Implement the doPassiveScan method of IScannerCheck interface
    Burp Scanner invokes this method for each base request/response that is
    passively scanned.
    """

    def doPassiveScan(self, baseRequestResponse):
        # Local variables used to store a list of ScanIssue objects
        scan_issues = []

        issues = []
        offset = array('i', [0, 0])

        # Using the regular expression, find all occurrences in the base
        # response
        matches = re.compile('\/\/\s?(todo|fix)', flags=re.IGNORECASE).findall(
            self._helpers.bytesToString(
                baseRequestResponse.getResponse()
            )
        )

        # Place marker(s)
        for match in matches:
            offsets = []

            # Find the start of the match
            start = self._helpers.indexOf(baseRequestResponse.getResponse(
            ), match, True, 0, len(baseRequestResponse.getResponse()))

            # Determine location and length of marker
            offset[0] = start
            offset[1] = start + len(match)
            offsets.append(offset)

            # Create a marking the matched value in the response.
            issues.append(
                StdScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(
                        baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(
                        baseRequestResponse, None, offsets)],
                    issuename,
                    issuelevel,
                    issuedetail.replace("$rut$", match)
                )
            )

        # Finally, per the interface contract, doPassiveScan needs to return a
        # list of scan issues, if any, and None otherwise
        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

    """
    Function for intercepting messages that go through the proxy.
    The 'message' variable is of the type IInterceptedProxyMessage
    """

    def processProxyMessage(self, messageIsRequest, message):

        # We only want requests
        if messageIsRequest:
            request = self._helpers.bytesToString(
                message.getMessageInfo().getRequest())

            # Hightlight all POST request
            if request.startswith("POST"):
                message.getMessageInfo().setHighlight('blue')
