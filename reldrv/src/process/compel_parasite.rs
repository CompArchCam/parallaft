use compel::compel_sys::parasite_ctl;

extern "C" {
    pub fn parasite_setup_c_header_wrapper(ctl: *mut parasite_ctl);
}

pub trait ParasiteCtlSetupHeaderExt {
    fn setup_c_header(&mut self);
}

impl<T, R> ParasiteCtlSetupHeaderExt for compel::ParasiteCtl<T, R>
where
    T: Send + Copy,
    R: Send + Copy,
{
    fn setup_c_header(&mut self) {
        unsafe { parasite_setup_c_header_wrapper(self.as_mut_ptr()) };
    }
}
