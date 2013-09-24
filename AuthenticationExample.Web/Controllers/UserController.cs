﻿using System;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using AppHarbor.Web.Security;
using AuthenticationExample.Web.Model;
using AuthenticationExample.Web.PersistenceSupport;
using AuthenticationExample.Web.ViewModels;

namespace AuthenticationExample.Web.Controllers
{
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
		public ActionResult Register()
		{
			return View();
		}

		[HttpPost]
		public ActionResult Register(RegisterModel registerModel)
		{
			if (_repository.GetAll<User>().Any(x => x.Username == registerModel.Username))
			{
				ModelState.AddModelError("Username", "Username is already in use");
			}

			if (ModelState.IsValid)
			{
				var user = new User
				{
					Id = Guid.NewGuid(),
					Username = registerModel.Username,
					EmailAddress = registerModel.EmailAddress,
					Password = Cryptography.Hash(registerModel.Password),
				};

				_repository.SaveOrUpdate(user);

				_authenticator.SetCookie(user.Username);

				return RedirectToAction("Index", "Home");
			}

			return View(registerModel);
		}

		[HttpGet]
		[Authorize]
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
