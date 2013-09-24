using System;
using System.Security.Cryptography;

namespace AuthenticationExample.Web.Controllers
{
	using System.Collections.Generic;
	using System.Linq;
	using System.Text;

	public static class Cryptography
	{
		private const int Pbkdf2SubkeyLength = 32;
		private const int SaltSize = 16;

		public static string Hash(string password, int iterations = 100000)
		{
			if (password == null) throw new ArgumentNullException("password");

			byte[] salt;
			byte[] bytes;
			using (var algo = new Rfc2898DeriveBytes(password, SaltSize, iterations))
			{
				salt = algo.Salt;
				bytes = algo.GetBytes(Pbkdf2SubkeyLength);
			}

			var iters = BitConverter.GetBytes(iterations);
			if (!BitConverter.IsLittleEndian)
				Array.Reverse(iters);

			var parts = new byte[54];
			Buffer.BlockCopy(salt, 0, parts, 1, SaltSize);
			Buffer.BlockCopy(bytes, 0, parts, 17, Pbkdf2SubkeyLength);
			Buffer.BlockCopy(iters, 0, parts, 50, sizeof(int));
			return Convert.ToBase64String(parts);
		}

		public static bool Verify(string hashedPassword, string password)
		{
			if (hashedPassword == null) throw new ArgumentNullException("hashedPassword");
			if (password == null) throw new ArgumentNullException("password");

			var parts = Convert.FromBase64String(hashedPassword);
			if (parts.Length != 54 || parts[0] != 0)
				return false;

			var salt = new byte[SaltSize];
			Buffer.BlockCopy(parts, 1, salt, 0, SaltSize);

			var bytes = new byte[Pbkdf2SubkeyLength];
			Buffer.BlockCopy(parts, 17, bytes, 0, Pbkdf2SubkeyLength);

			var iters = new byte[sizeof(int)];
			Buffer.BlockCopy(parts, 50, iters, 0, sizeof(int));

			if (!BitConverter.IsLittleEndian)
				Array.Reverse(iters);

			var iterations = BitConverter.ToInt32(iters, 0);

			byte[] challengeBytes;
			using (var algo = new Rfc2898DeriveBytes(password, salt, iterations))
				challengeBytes = algo.GetBytes(32);

			return ByteArraysEqual(bytes, challengeBytes);
		}

		private static bool ByteArraysEqual(byte[] a, byte[] b)
		{
			if (ReferenceEquals(a, b)) return true;
			if (a == null || b == null || a.Length != b.Length) return false;

			var flag = true;
			for (var i = 0; i < a.Length; i++)
				flag = flag & a[i] == b[i];

			return flag;
		}

		// Taken from stackoverflow discussion: http://stackoverflow.com/a/8996788/366550
		public static string RandomString(int length, string allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
		{
			if (length < 0) throw new ArgumentOutOfRangeException("length", "length cannot be less than zero.");
			if (string.IsNullOrEmpty(allowedChars)) throw new ArgumentException("allowedChars may not be empty.");

			const int byteSize = 0x100;
			var allowedCharSet = new HashSet<char>(allowedChars).ToArray();
			if (byteSize < allowedCharSet.Length) throw new ArgumentException(String.Format("allowedChars may contain no more than {0} characters.", byteSize));

			// Guid.NewGuid and System.Random are not particularly random. By using a
			// cryptographically-secure random number generator, the caller is always
			// protected, regardless of use.
			using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
			{
				var result = new StringBuilder();
				var buf = new byte[128];
				while (result.Length < length)
				{
					rng.GetBytes(buf);
					for (var i = 0; i < buf.Length && result.Length < length; ++i)
					{
						// Divide the byte into allowedCharSet-sized groups. If the
						// random value falls into the last group and the last group is
						// too small to choose from the entire allowedCharSet, ignore
						// the value in order to avoid biasing the result.
						var outOfRangeStart = byteSize - (byteSize % allowedCharSet.Length);
						if (outOfRangeStart <= buf[i]) continue;
						result.Append(allowedCharSet[buf[i] % allowedCharSet.Length]);
					}
				}
				return result.ToString();
			}
		}
	}
}
