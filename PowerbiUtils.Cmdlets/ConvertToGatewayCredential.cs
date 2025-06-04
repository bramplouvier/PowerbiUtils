using System;
using System.Management.Automation;

using PowerbiUtils.Engine;

namespace PowerbiUtils.Cmdlets
{
    [Cmdlet(VerbsData.ConvertTo, "GatewayCredential")]
    [OutputType(typeof(string))]
    public class ConvertToGatewayCredentialCommand : PSCmdlet
    {
        [Parameter(Mandatory = true)]
        public PSCredential Credential { get; set; }

        [Parameter(Mandatory = true)]
        public string GatewayKeyModulus { get; set; }

        [Parameter(Mandatory = true)]
        public string GatewayKeyExponent { get; set; }

        [Parameter(Mandatory = false)]
        public CredentialType CredentialType { get; set; } = CredentialType.Windows;

        // This method gets called once for each cmdlet in the pipeline when the pipeline starts executing
        protected override void BeginProcessing()
        {
            WriteVerbose("Begin!");
        }

        // This method will be called for each input received from the pipeline to this cmdlet; if no input is received, this method is not called

        protected override void ProcessRecord()
        {
            var encryptedCredential = GatewayCredentialEncryptor.encrypt(
                this.GatewayKeyExponent,
                this.GatewayKeyModulus,
                this.Credential
            );
            WriteObject(encryptedCredential);
        }

        // This method will be called once at the end of pipeline execution; if no input is received, this method is not called
        protected override void EndProcessing()
        {
            WriteVerbose("End!");
        }
    }
    
    public enum CredentialType
    {
        /// <summary> Basic. </summary>
        Basic,
        /// <summary> Windows. </summary>
        Windows,
        /// <summary> Anonymous. </summary>
        Anonymous,
        /// <summary> OAuth2. </summary>
        OAuth2,
        /// <summary> Key. </summary>
        Key,
        /// <summary> SAS. </summary>
        SAS
    }
}
