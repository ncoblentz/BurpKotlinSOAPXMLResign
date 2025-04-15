import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.Selection
import burp.api.montoya.ui.editor.EditorOptions
import burp.api.montoya.ui.editor.RawEditor
import burp.api.montoya.ui.editor.extension.EditorCreationContext
import burp.api.montoya.ui.editor.extension.EditorMode
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor
import com.nickcoblentz.montoya.settings.StringExtensionSetting
import java.awt.Component


class ResignSOAPHttpRequestEditor(private val api: MontoyaApi, creationContext: EditorCreationContext?, var pfxCertificateLocationSetting : StringExtensionSetting, var pfxCertificatePasswordSetting : StringExtensionSetting) : ExtensionProvidedHttpRequestEditor {
    private var editor: RawEditor
    private var data : ByteArray = ByteArray.byteArray("")
    private var httpRequestResponse : HttpRequestResponse? = null

    init {
        if(creationContext?.editorMode()?.equals(EditorMode.READ_ONLY) == true)
            editor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY,EditorOptions.WRAP_LINES)
        else
            editor = api.userInterface().createRawEditor(EditorOptions.WRAP_LINES)
    }


    // Save the latest HTTP request and response in class instance variables
    // Parse and beautify the `data` parameter if present and store it in a class instance variable
    // Set the HTTP editor's content with that value
    override fun setRequestResponse(newHttpRequestResponse: HttpRequestResponse?) {
        api.logging().logToOutput("SetRqRs")
        httpRequestResponse = newHttpRequestResponse
        data=ByteArray.byteArray("")
        httpRequestResponse?.request()?.let {
            api.logging().logToOutput("found request")
            api.logging().logToOutput(it.bodyToString())
            data=it.body()
        }
        api.logging().logToOutput("Exited looking for data")

        api.logging().logToOutput("attempt pretty print")
        val output = data.toString()// prettyPrintXmlString(data.toString())
        api.logging().logToOutput(output)
        editor.contents = ByteArray.byteArray(output)
    }

    // When should we show the text editor. The criteria below checks:
    // - the HTTP request isn't null
    // - it includes a "transport" parameter with value "longPolling"
    // - it has a "data" parameter
    override fun isEnabledFor(httpRequestResponse: HttpRequestResponse?): Boolean {
        httpRequestResponse?.request()?.let {
            return it.bodyToString().contains("<SOAP-SEC:Signature")
        }
        return false
    }

    // Set the name of the tab
    override fun caption(): String {
        return "Resign SOAP Data"
    }

    // Return the Swing Component to Burp
    override fun uiComponent(): Component {
        return editor.uiComponent()
    }

    // Provide the selected (highlighted) data when asked for
    override fun selectedData(): Selection? {
        return if (editor.selection().isPresent) editor.selection().get() else null

    }

    // Did the user modify the content inside the text editor?
    override fun isModified(): Boolean {
        return editor.isModified
    }

    // When it's time to send the request or a user clicks on another tab, we need to process any changes and update the HTTP request
    override fun getRequest(): HttpRequest? {

        val request: HttpRequest?
        api.logging().logToOutput("get request")
        if (editor.isModified) {
            api.logging().logToOutput("resigning")
            val newSignedXmlBody = resign(editor.contents.toString(),pfxCertificateLocationSetting.currentValue,pfxCertificatePasswordSetting.currentValue)
            api.logging().logToOutput("resigned")
            api.logging().logToOutput(newSignedXmlBody)
            request = httpRequestResponse?.request()?.withBody(newSignedXmlBody)
            api.logging().logToOutput("update request body")
        }
        else
            request=httpRequestResponse?.request()


        return request
    }
}