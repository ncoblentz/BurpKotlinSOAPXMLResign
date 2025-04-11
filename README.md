# Burp Montoya Regex Match/Replace Session Action

_By [Nick Coblentz](https://www.linkedin.com/in/ncoblentz/)_

__This Burp Extension is made possible by [Virtue Security](https://www.virtuesecurity.com), the Application Penetration Testing consulting company I work for.__

## About

This project provides an example of recalculating the XML signature for a SOAP request using a PFX located at `~/Documents/cert.pfx` containing a public and private key with the passphrase `privatekey`

### How to Build a Project

#### Setup

This project was initially created using the template found at: https://github.com/ncoblentz/KotlinBurpExtensionBase. That template's README.md describes how to:
- Build this and other projects based on the template
- Load the built jar file in Burp Suite
- Debug Burp Suite extensions using IntelliJ
- Provides links to documentation for building Burp Suite Plugins