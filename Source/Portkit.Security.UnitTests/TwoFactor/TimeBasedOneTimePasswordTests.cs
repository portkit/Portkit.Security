using System;
using System.Threading;
using NUnit.Framework;
using Portkit.Security.Crypto;
using Portkit.Security.TwoFactor;

namespace Portkit.Security.UnitTests.TwoFactor
{
    [TestFixture]
    public class TimeBasedOneTimePasswordTests
    {
        private const string SHARED_KEY = "B2374TNIQ3HKC446";

        [Test]
        public void ShouldGenerateCorrectCodeForGivenTime()
        {
            var timeCounterProvider = new TimeCounterProvider();
            var timeSnapshot = new DateTime(2017, 1, 20, 12, 47, 31);
            var otp = new OneTimePassword(new Sha1(), SHARED_KEY);
            var code = otp.Generate(timeCounterProvider.GetCounter(timeSnapshot));
            Assert.AreEqual("041809", code);
        }

        [Test]
        public void ShouldGenerateTimeBasedOneTimePassword()
        {
            var timeStep = TimeSpan.FromMilliseconds(500);
            var timeCounterProvider = new TimeCounterProvider(timeStep);
            var otp = new OneTimePassword(new Sha1(), SHARED_KEY);

            var firstCode = otp.Generate(timeCounterProvider.GetCounter());

            // Wait twice the time step
            Thread.Sleep(timeStep + timeStep);

            var secondCode = otp.Generate(timeCounterProvider.GetCounter());

            Assert.AreNotEqual(firstCode, secondCode);
        }
    }
}