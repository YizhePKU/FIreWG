use hifitime::Epoch;

#[link(name = "ntoskrnl")]
extern "system" {
    // KeQuerySystemTime is a macro and cannot be linked against,
    // so use KeQuerySystemTimePrecise instead (check wdm.h).
    pub fn KeQuerySystemTimePrecise(current_time: *mut u64);
}

pub fn now() -> Epoch {
    // Mock time for testing
    #[cfg(all(test, feature = "mock-instant"))]
    {
        use crate::mock_instant::MockClock;
        MockClock::now()
    }
    // Windows real time for testing
    #[cfg(all(test, not(feature = "mock-instant")))]
    {
        use windows::Win32::System::SystemInformation::GetSystemTime;
        let time = unsafe { GetSystemTime() };
        Epoch::from_gregorian_utc(
            time.wYear as i32,
            time.wMonth as u8,
            time.wDay as u8,
            time.wHour as u8,
            time.wMinute as u8,
            time.wSecond as u8,
            (time.wMilliseconds as u32) * 1_000_000,
        )
    }
    // Kernel time
    #[cfg(not(test))]
    {
        let system_time = unsafe {
            let mut buf = 0;
            KeQuerySystemTimePrecise(&mut buf);
            buf
        };
        let windows_epoch = Epoch::from_gregorian_utc_at_midnight(2001, 1, 1)
            - hifitime::Unit::Day * 400 * 365
            - hifitime::Unit::Day * 97;
        let diff = hifitime::Duration::from_total_nanoseconds((system_time as i128) * 100);
        let now = windows_epoch + diff;

        now
    }
}
