using System.ComponentModel.DataAnnotations;

namespace AuthenticationExample.Web.ViewModels
{
	public class CompleteRegistrationModel
	{
		[Required]
		[DataType(DataType.Text)]
		public string Username { get; set; }
		[Required]
		[DataType(DataType.EmailAddress)]
		[EmailAddress]
		public string EmailAddress { get; set; }
		[Required]
		[DataType(DataType.Password)]
		public string Password { get; set; }
		[Required]
		public string VerificationCode { get; set; }
	}
}
