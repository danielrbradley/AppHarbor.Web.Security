using System;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using AppHarbor.Web.Security;
using AuthenticationExample.Web.Model;
using AuthenticationExample.Web.PersistenceSupport;
using AuthenticationExample.Web.ViewModels;

namespace AuthenticationExample.Web.Controllers
{
	[Authorize]
	public class UserController : Controller
	{
		private readonly IAuthenticator _authenticator;
		private readonly IRepository _repository;

		public UserController(IAuthenticator authenticator, IRepository repository)
		{
			_authenticator = authenticator;
			_repository = repository;
		}

		[HttpGet]
		public ActionResult Show()
		{
			var user = _repository.GetAll<User>().SingleOrDefault(x => x.Username == User.Identity.Name);
			if (user == null)
			{
				throw new HttpException(404, "Not found");
			}

			return View(user);
		}
	}
}
