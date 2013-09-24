using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using AuthenticationExample.Web.EmailModels;

namespace AuthenticationExample.Web.EmailSupport
{
	using System.IO;

	public class RegistrationEmailer : IEmailer<RegistrationConfirmation>
	{
		public void Send(RegistrationConfirmation model)
		{
			// For demonstration only.
			// This should be replaced with sending a real email to the user
			// with a hyperlink to complete their registration.
			var logPath = System.Web.HttpContext.Current.Server.MapPath("~/RegistrationEmails.log");

			var message = string.Format(
				"Registration recieved: Username: {0}; Email Address: {1}; Verification Code: {2}",
				model.Username,
				model.EmailAddress,
				model.VerificationCode);

			var logMessage = string.Format("{0:u} {1}\r\n", DateTime.Now, message);

			File.AppendAllText(logPath, logMessage);
		}
	}
}
