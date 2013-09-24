namespace AuthenticationExample.Web.Model
{
	using System;

	public class Registration : User
	{
		public virtual DateTime Expires { get; set; }
		public virtual string VerificationCode { get; set; }
	}
}
