using System;

namespace Portkit.Security.TwoFactor
{
    public class TimeCounterProvider
    {
        private const long UNIX_EPOCH = 621355968000000000;
        private readonly Func<DateTime> _now;

        public TimeSpan TimeStep { get; }

        public DateTime Now => _now.Invoke();

        public TimeCounterProvider(TimeSpan timeStep, Func<DateTime> getCurrentTime)
        {
            _now = getCurrentTime;
            TimeStep = timeStep;
        }

        public TimeCounterProvider(TimeSpan timeStep) :
            this(timeStep, () => DateTime.UtcNow)
        {
        }

        public TimeCounterProvider() :
            this(TimeSpan.FromSeconds(30))
        {
        }

        public long GetCounter(DateTime dateTime) => (long)(GetTimestamp(dateTime) / TimeStep.TotalSeconds);

        public long GetCounter() => GetCounter(Now);

        public TimeSpan GetExpirationInterval()
        {
            var now = GetTimestamp(Now);
            var next = (long)(now / TimeStep.TotalSeconds) + 1L;
            var remainingSeconds = (next - (now / TimeStep.TotalSeconds)) * TimeStep.TotalSeconds;
            return TimeSpan.FromSeconds(remainingSeconds);
        }

        private static long GetTimestamp(DateTime dateTime) =>
            (dateTime.ToUniversalTime().Ticks - UNIX_EPOCH) / TimeSpan.TicksPerSecond;
    }
}