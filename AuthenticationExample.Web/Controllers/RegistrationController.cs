using System;
using System.Linq;
using System.Web.Mvc;
using AppHarbor.Web.Security;
using AuthenticationExample.Web.Model;
using AuthenticationExample.Web.PersistenceSupport;
using AuthenticationExample.Web.ViewModels;

namespace AuthenticationExample.Web.Controllers
{
	using System.Net;

	using AuthenticationExample.Web.EmailModels;
	using AuthenticationExample.Web.EmailSupport;

	public class RegistrationController : Controller
	{
		private readonly IAuthenticator _authenticator;
		private readonly IRepository _repository;

		private readonly IEmailer<RegistrationConfirmation> _confirmationEmailer;

		public RegistrationController(IAuthenticator authenticator, IRepository repository, IEmailer<RegistrationConfirmation> confirmationEmailer)
		{
			_authenticator = authenticator;
			_repository = repository;
			_confirmationEmailer = confirmationEmailer;
		}

		[HttpGet]
		public ActionResult Start()
		{
			return View();
		}

		[HttpPost]
		public ActionResult Start(StartRegistrationModel startRegistrationModel)
		{
			if (_repository.GetAll<User>().Any(x => x.Username == startRegistrationModel.Username))
			{
				ModelState.AddModelError("Username", "Username is already in use");
			}

			if (_repository.GetAll<User>().Any(x => x.EmailAddress == startRegistrationModel.EmailAddress))
			{
				ModelState.AddModelError("EmailAddress", "Email address is already in use");
			}

			if (ModelState.IsValid)
			{
				var verificationCode = Cryptography.RandomString(12);
				var user = new Registration
				{
					Id = Guid.NewGuid(),
					Username = startRegistrationModel.Username,
					EmailAddress = startRegistrationModel.EmailAddress,
					Password = Cryptography.Hash(startRegistrationModel.Password),
					Expires = DateTime.UtcNow.AddDays(3),
					VerificationCode = Cryptography.Hash(verificationCode)
				};

				var registrationConfirmation = new RegistrationConfirmation
				{
					Username = startRegistrationModel.Username,
					EmailAddress = startRegistrationModel.EmailAddress,
					VerificationCode = verificationCode
				};
				_confirmationEmailer.Send(registrationConfirmation);

				_repository.SaveOrUpdate(user);

				return RedirectToAction(
					"Complete", "Registration", new { startRegistrationModel.Username, startRegistrationModel.EmailAddress });
			}

			return View(startRegistrationModel);
		}

		public ActionResult Complete(CompleteRegistrationModel completeRegistrationModel)
		{
			if (completeRegistrationModel == null) completeRegistrationModel = new CompleteRegistrationModel();

			if (Request.HttpMethod == "GET")
			{
				return View(completeRegistrationModel);
			}

			if (Request.HttpMethod != "POST")
			{
				return new HttpStatusCodeResult((int)HttpStatusCode.MethodNotAllowed);
			}

			if (ModelState.IsValid)
			{
				var registrations = from r in _repository.GetAll<Registration>()
									where
										r.Username == completeRegistrationModel.Username
										&& r.EmailAddress == completeRegistrationModel.EmailAddress
									orderby r.Expires descending
									select r;

				var registration = registrations.FirstOrDefault();

				if (RegistrationIsValid(registration, completeRegistrationModel))
				{
					var user = new User
								   {
									   Id = Guid.NewGuid(),
									   Username = registration.Username,
									   EmailAddress = registration.EmailAddress,
									   Password = registration.Password
								   };

					_repository.SaveOrUpdate(user);

					_authenticator.SetCookie(user.Username);

					return RedirectToAction("Index", "Home");
				}
			}

			return View(completeRegistrationModel);
		}

		private static bool RegistrationIsValid(Registration latestRegistration, CompleteRegistrationModel completeRegistrationModel)
		{
			if (latestRegistration == null) return false;

			if (latestRegistration.Expires < DateTime.UtcNow) return false;

			if (!Cryptography.Verify(latestRegistration.Password, completeRegistrationModel.Password)) return false;

			if (!Cryptography.Verify(latestRegistration.VerificationCode, completeRegistrationModel.VerificationCode)) return false;

			return true;
		}
	}
}
