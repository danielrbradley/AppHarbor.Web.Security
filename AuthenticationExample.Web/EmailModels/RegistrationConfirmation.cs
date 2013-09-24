namespace AuthenticationExample.Web.EmailModels
{
	public class RegistrationConfirmation
	{
		public string Username { get; set; }
		public string EmailAddress { get; set; }
		public string VerificationCode { get; set; }
	}
}
