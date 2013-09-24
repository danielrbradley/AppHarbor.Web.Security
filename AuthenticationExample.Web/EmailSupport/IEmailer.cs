using System;
using System.Linq;
using AuthenticationExample.Web.Model;

namespace AuthenticationExample.Web.EmailSupport
{
	public interface IEmailer<T>
	{
		void Send(T model);
	}
}
