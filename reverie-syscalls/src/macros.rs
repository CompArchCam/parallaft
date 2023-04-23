/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/// Creates a type-safe syscall by generating much of the boilerplate needed to
/// do conversion from the raw syscall registers into Rust types.
macro_rules! typed_syscall {
    // This macro is pretty big, but most of the rules are for matching and
    // collecting potentially different types of syscall arguments. The easiest
    // way to read this macro is bottom-up.
    //
    // There are four "types" of syscall arguments that we need to match on:
    //  1. Non-optional, uncustomized entries: `my_arg: MyType,`
    //  2. Non-optional, customized entries: `my_arg: fn(&self) -> MyType {...},`
    //  3. Optional, uncustomized entries: `my_arg?: MyType,`
    //  4. Optional, customized entries: `my_arg?: fn(&self) -> MyType {...},`
    //
    // Once a rule matches one of these, we separate the optional from the
    // non-optional arguments. We do this so that the optional arguments are
    // always at the end of the argument list and so that during display, we can
    // avoid printing it out if it is `None`.

    // Exit rule
    (@make_syscall
        {
            vis: $vis:vis,
            name: $Name:ident,
            attrs: [$(#[$attrs:meta])*],
            ret: $ret:ty,
            doc: $doc:expr,
            // Required arguments
            required: [$({
                $req:ident,

                // The 'getter' function.
                $(#[$req_get_meta:meta])*
                ($($req_get_args:tt)*) -> $req_type:ty {
                    $($req_get_impl:tt)*
                }

                // The 'setter' function.
                $(#[$req_set_meta:meta])*
                ($($req_set_args:tt)*) -> $req_set_type:ty {
                    $($req_set_impl:tt)*
                }
            },)*],
            // Optional arguments
            optional: [$({
                $opt:ident,

                // The 'getter' function.
                $(#[$opt_get_meta:meta])*
                ($($opt_get_args:tt)*) -> $opt_type:ty {
                    $($opt_get_impl:tt)*
                }

                // The 'setter' function.
                $(#[$opt_set_meta:meta])*
                ($($opt_set_args:tt)*) -> $opt_set_type:ty {
                    $($opt_set_impl:tt)*
                }
            },)*],
            may_read: [$($may_read_entries:tt)*],
            may_written: [$($may_written_entries:tt)*],
            impl_may_read: $impl_may_read:ident,
            impl_may_write: $impl_may_write:ident,
            may_read_specified_only: $may_read_specified_only:ident,
            may_write_specified_only: $may_write_specified_only:ident,
        }
    ) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        $(#[$attrs])*
        #[doc = $doc]
        $vis struct $Name {
            raw: ::syscalls::SyscallArgs,
        }

        $(#[$attrs])*
        impl Default for $Name {
            fn default() -> Self {
                Self {
                    raw: ::syscalls::SyscallArgs::new(0, 0, 0, 0, 0, 0),
                }
            }
        }

        $(#[$attrs])*
        impl $crate::SyscallInfo for $Name {
            type Return = Result<$ret, $crate::Errno>;

            #[inline]
            fn name(&self) -> &'static str {
                Self::NAME
            }

            #[inline]
            fn number(&self) -> ::syscalls::Sysno {
                Self::NUMBER
            }

            fn into_parts(self) -> (::syscalls::Sysno, ::syscalls::SyscallArgs) {
                (Self::NUMBER, self.raw)
            }
        }

        $(#[$attrs])*
        impl $Name {
            ::paste::paste! {
                /// The name of the syscall.
                pub const NAME: &'static str = stringify!([<$Name:snake>]);

                /// The syscall number.
                pub const NUMBER: ::syscalls::Sysno = ::syscalls::Sysno::[<$Name:snake>];
            }

            /// Creates the syscall. Use the `with_*` functions to build up the
            /// arguments to this syscall.
            pub fn new() -> Self {
                Self::default()
            }

            // Generate getter functions.
            $(
                /// Gets this argument's value.
                $(#[$req_get_meta])*
                #[allow(clippy::len_without_is_empty)]
                pub fn $req($($req_get_args)*) -> $req_type {
                    $($req_get_impl)*
                }
            )*

            $(
                /// Gets this optional argument's value. Returns `None` if it is not set.
                $(#[$opt_get_meta])*
                pub fn $opt($($opt_get_args)*) -> $opt_type {
                    $($opt_get_impl)*
                }
            )*

            // Generate setter functions
            ::paste::paste! {
                $(
                    /// Sets this argument to the given value.
                    $(#[$req_set_meta])*
                    pub fn [<with_ $req>]($($req_set_args)*) -> $req_set_type {
                        $($req_set_impl)*
                    }
                )*

                $(
                    /// Sets this optional argument to the given value.
                    $(#[$opt_set_meta])*
                    pub fn [<with_ $opt>]($($opt_set_args)*) -> $opt_set_type {
                        $($opt_set_impl)*
                    }
                )*
            }
        }

        $(#[$attrs])*
        impl From<::syscalls::SyscallArgs> for $Name {
            fn from(raw: ::syscalls::SyscallArgs) -> Self {
                $Name { raw }
            }
        }

        $(#[$attrs])*
        impl From<$Name> for ::syscalls::SyscallArgs {
            fn from(syscall: $Name) -> Self {
                syscall.raw
            }
        }

        typed_syscall! {
            @impl_display
            $Name,
            [$($req,)*],
            [$($opt,)*],
            attrs: [$(#[$attrs])*],
        }

        typed_syscall! {
            @impl_may_read
            $impl_may_read,
            $may_read_specified_only,
            $Name,
            [$($may_read_entries)*]
            attrs: [$(#[$attrs])*],
        }

        typed_syscall! {
            @impl_may_write
            $impl_may_write,
            $may_write_specified_only,
            $Name,
            [$($may_written_entries)*]
            attrs: [$(#[$attrs])*],
        }
    };

    // Implement SyscallMayRead
    (@impl_may_read
        true,
        true,
        $Name:ident,
        [$([$method:ident, $($entries:ident),*])*]
        attrs: [$(#[$attrs:meta])*],
    ) => {
        $(#[$attrs])*
        impl<'a, M: MemoryAccess> $crate::syscalls::may_rw::SyscallMayRead<'a, M> for $Name {
            fn may_read(&'a self, memory: &'a M) -> Result<Box<[::reverie_memory::AddrSlice<'a, u8>]>, $crate::Errno> {
                let builder = $crate::syscalls::may_rw::RangesSyscallMayReadBuilder::new(memory);

                builder
                    $(
                        .$method($(self.$entries()),*)
                    )*

                .build()
            }
        }
    };

    // Implement SyscallMayRead that potentially reads anything
    (@impl_may_read
        true,
        false,
        $Name:ident,
        [$([$method:ident, $($entries:ident),*])*]
        attrs: [$(#[$attrs:meta])*],
    ) => {
        $(#[$attrs])*
        impl<'a, M: MemoryAccess> $crate::syscalls::may_rw::SyscallMayRead<'a, M> for $Name {
            fn may_read(&'a self, memory: &'a M) -> Result<Box<[::reverie_memory::AddrSlice<'a, u8>]>, $crate::Errno> {
                $crate::syscalls::may_rw::RangesSyscallMayReadBuilder::new(memory).may_read_anything().build()
            }
        }
    };

    // Do nothing if #[no_impl_may_read] is specified
    (@impl_may_read
        false,
        $may_read_specified_only:ident,
        $Name:ident,
        [$($may_read_entries:tt)*]
        attrs: [$(#[$attrs:meta])*],
    ) => {};

    // Implement SyscallMayWrite
    (@impl_may_write
        true,
        true,
        $Name:ident,
        [$([$method:ident, $($entries:ident),*])*]
        attrs: [$(#[$attrs:meta])*],
    ) => {
        $(#[$attrs])*
        impl<'a, M: MemoryAccess> $crate::syscalls::may_rw::SyscallMayWrite<'a, M> for $Name {
            fn may_write(&'a self, memory: &'a M) -> Result<Box<[::reverie_memory::AddrSliceMut<'a, u8>]>, $crate::Errno> {
                let builder = $crate::syscalls::may_rw::RangesSyscallMayWriteBuilder::new(memory);

                builder
                    $(
                        .$method($(self.$entries()),*)
                    )*

                .build()
            }
        }
    };

    // Implement SyscallMayWrite that potentially writes anything
    (@impl_may_write
        true,
        false,
        $Name:ident,
        [$([$method:ident, $($entries:ident),*])*]
        attrs: [$(#[$attrs:meta])*],
    ) => {
        $(#[$attrs])*
        impl<'a, M: MemoryAccess> $crate::syscalls::may_rw::SyscallMayWrite<'a, M> for $Name {
            fn may_write(&'a self, memory: &'a M) -> Result<Box<[::reverie_memory::AddrSliceMut<'a, u8>]>, $crate::Errno> {
                $crate::syscalls::may_rw::RangesSyscallMayWriteBuilder::new(memory).may_write_anything().build()
            }
        }
    };

    // Do nothing if #[no_impl_may_write] is specified
    (@impl_may_write
        false,
        $may_read_specified_only:ident,
        $Name:ident,
        [$($may_written_entries:tt)*]
        attrs: [$(#[$attrs:meta])*],
    ) => {};

    // Display zero args
    (@impl_display
        $Name:ident,
        [],
        [],
        attrs: [$(#[$attrs:meta])*],
    ) => {
        $(#[$attrs])*
        impl $crate::Displayable for $Name {
            fn fmt<M: $crate::MemoryAccess>(
                &self,
                _memory: &M,
                _outputs: bool,
                f: &mut ::core::fmt::Formatter,
            ) -> ::core::fmt::Result {
                write!(f, "{}()", Self::NAME)
            }
        }
    };

    // Display zero required args, but some optional args
    (@impl_display
        $Name:ident,
        [],
        [$optional:ident, $($optional_tail:ident,)*],
        attrs: [$(#[$attrs:meta])*],
    ) => {
        $(#[$attrs])*
        impl $crate::Displayable for $Name {
            fn fmt<M: $crate::MemoryAccess>(
                &self,
                memory: &M,
                outputs: bool,
                f: &mut ::core::fmt::Formatter,
            ) -> ::core::fmt::Result {
                write!(f, "{}(", Self::NAME)?;

                self.$optional().fmt(memory, outputs, f)?;

                $(
                    if let Some(arg) = self.$optional_tail() {
                        f.write_str(", ")?;
                        arg.fmt(memory, outputs, f)?;
                    }
                )*

                f.write_str(")")
            }
        }
    };

    // Display one or more required arguments.
    (@impl_display
        $Name:ident,
        [$req:ident, $($req_tail:ident,)*],
        [$($optional_tail:ident,)*],
        attrs: [$(#[$attrs:meta])*],
    ) => {
        $(#[$attrs])*
        impl $crate::Displayable for $Name {
            fn fmt<M: $crate::MemoryAccess>(
                &self,
                memory: &M,
                outputs: bool,
                f: &mut ::core::fmt::Formatter,
            ) -> ::core::fmt::Result {
                write!(f, "{}(", Self::NAME)?;

                self.$req().fmt(memory, outputs, f)?;

                $(
                    f.write_str(", ")?;
                    $crate::Displayable::fmt(&self.$req_tail(), memory, outputs, f)?;
                )*

                $(
                    // Display all optional arguments at the end.
                    if let Some(arg) = self.$optional_tail() {
                        f.write_str(", ")?;
                        $crate::Displayable::fmt(&arg, memory, outputs, f)?;
                    }
                )*

                f.write_str(")")
            }
        }
    };

    // Done accumulating entries
    (@accumulate_entries
        {
            vis: $vis:vis,
            name: $Name:ident,
            attrs: [$(#[$attrs:meta])*],
            ret: $ret:ty,
            impl_may_read: $impl_may_read:ident,
            impl_may_write: $impl_may_write:ident,
            may_read_specified_only: $may_read_specified_only:ident,
            may_write_specified_only: $may_write_specified_only:ident,
        },
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        [$($req_entries:tt)*],
        [$($optional_entries:tt)*],
        [$($raw:ident,)*],
    ) => {
        ::paste::paste! {
            typed_syscall! {
                @make_syscall
                {
                    vis: $vis,
                    name: $Name,
                    attrs: [$(#[$attrs])*],
                    ret: $ret,
                    // Generate a handy link to the syscall in the doc comment.
                    doc: concat!(
                        "See [", stringify!([<$Name:snake>]), "(2)]",
                        "(http://man7.org/linux/man-pages/man2/", stringify!([<$Name:snake>]),
                        ".2.html) for info on this syscall."
                    ),
                    required: [$($req_entries)*],
                    optional: [$($optional_entries)*],
                    may_read: [$($may_read_entries)*],
                    may_written: [$($may_written_entries)*],
                    impl_may_read: $impl_may_read,
                    impl_may_write: $impl_may_write,
                    may_read_specified_only: $may_read_specified_only,
                    may_write_specified_only: $may_write_specified_only,
                }
            }
        }
    };

    // Munch a required entry with path_ptr_may_read attribute
    (@accumulate_entries
        $prefix:tt,
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        [$($req_entries:tt)*],
        [$($optional_entries:tt)*],
        [$($rawtail:ident,)*],
        #[path_ptr_may_read]
        $(#[$meta:meta])*
        $entry:ident: $t:ty,
        $($tail:tt)*
    ) => {
        typed_syscall! {
            @accumulate_entries
            $prefix,
            [$($may_read_entries)* [may_read_path_ptr, $entry]],
            [$($may_written_entries)*],
            [$($req_entries)*],
            [$($optional_entries)*],
            [$($rawtail,)*],
            $(#[$meta])*
            $entry: $t,
            $($tail)*
        }
    };

    // Munch a required entry with object_may_read attribute
    (@accumulate_entries
        $prefix:tt,
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        [$($req_entries:tt)*],
        [$($optional_entries:tt)*],
        [$($rawtail:ident,)*],
        #[object_may_read]
        $(#[$meta:meta])*
        $entry:ident: $t:ty,
        $($tail:tt)*
    ) => {
        typed_syscall! {
            @accumulate_entries
            $prefix,
            [$($may_read_entries)* [may_read_object, $entry]],
            [$($may_written_entries)*],
            [$($req_entries)*],
            [$($optional_entries)*],
            [$($rawtail,)*],
            $(#[$meta])*
            $entry: $t,
            $($tail)*
        }
    };

    // Munch a required entry with buf_may_read_with_len attribute
    (@accumulate_entries
        $prefix:tt,
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        [$($req_entries:tt)*],
        [$($optional_entries:tt)*],
        [$($rawtail:ident,)*],
        #[buf_may_read_with_len = $len:ident]
        $(#[$meta:meta])*
        $entry:ident: $t:ty,
        $($tail:tt)*
    ) => {
        typed_syscall! {
            @accumulate_entries
            $prefix,
            [$($may_read_entries)* [may_read_buf_with_len, $entry, $len]],
            [$($may_written_entries)*],
            [$($req_entries)*],
            [$($optional_entries)*],
            [$($rawtail,)*],
            $(#[$meta])*
            $entry: $t,
            $($tail)*
        }
    };

    // Munch a required entry with object_may_written attribute
    (@accumulate_entries
        $prefix:tt,
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        [$($req_entries:tt)*],
        [$($optional_entries:tt)*],
        [$($rawtail:ident,)*],
        #[object_may_written]
        $(#[$meta:meta])*
        $entry:ident: $t:ty,
        $($tail:tt)*
    ) => {
        typed_syscall! {
            @accumulate_entries
            $prefix,
            [$($may_read_entries)*],
            [$($may_written_entries)* [may_write_object, $entry]],
            [$($req_entries)*],
            [$($optional_entries)*],
            [$($rawtail,)*],
            $(#[$meta])*
            $entry: $t,
            $($tail)*
        }
    };

    // Munch a required entry with buf_may_written_with_len attribute
    (@accumulate_entries
        $prefix:tt,
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        [$($req_entries:tt)*],
        [$($optional_entries:tt)*],
        [$($rawtail:ident,)*],
        #[buf_may_written_with_len = $len:ident]
        $(#[$meta:meta])*
        $entry:ident: $t:ty,
        $($tail:tt)*
    ) => {
        typed_syscall! {
            @accumulate_entries
            $prefix,
            [$($may_read_entries)*],
            [$($may_written_entries)* [may_write_buf_with_len, $entry, $len]],
            [$($req_entries)*],
            [$($optional_entries)*],
            [$($rawtail,)*],
            $(#[$meta])*
            $entry: $t,
            $($tail)*
        }
    };

    // Munch a required entry
    (@accumulate_entries
        $prefix:tt,
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        [$($req_entries:tt)*],
        [$($optional_entries:tt)*],
        [$raw:ident, $($rawtail:ident,)*],
        $(#[$meta:meta])*
        $entry:ident: $t:ty,
        $($tail:tt)*
    ) => {
        typed_syscall! {
            @accumulate_entries
            $prefix,
            [$($may_read_entries)*],
            [$($may_written_entries)*],
            [
                $($req_entries)*
                // Append the munched entry
                {
                    $entry,

                    $(#[$meta])*
                    (&self) -> $t {
                        $crate::FromToRaw::from_raw((self.raw).$raw)
                    }

                    $(#[$meta])*
                    (mut self, v: $t) -> Self {
                        (self.raw).$raw = $crate::FromToRaw::into_raw(v);
                        self
                    }
                },
            ],
            [$($optional_entries)*],
            [$($rawtail,)*],
            $($tail)*
        }
    };

    // Munch a required function entry
    (@accumulate_entries
        $prefix:tt,
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        [$($req_entries:tt)*],
        [$($optional_entries:tt)*],
        [$raw:ident, $($rawtail:ident,)*],
        $(#[$meta:meta])*
        $entry:ident: {
            $(#[$get_meta:meta])*
            fn get($($get_args:tt)*) -> $get_type:ty { $($get_impl:tt)* }

            $(#[$set_meta:meta])*
            fn set($($set_args:tt)*) -> $set_type:ty { $($set_impl:tt)* }
        },
        $($tail:tt)*
    ) => {
        typed_syscall! {
            @accumulate_entries
            $prefix,
            [$($may_read_entries)*],
            [$($may_written_entries)*],
            [
                $($req_entries)*
                // Append the munched entry
                {
                    $entry,

                    $(#[$meta])*
                    $(#[$get_meta])*
                    ($($get_args)*) -> $get_type { $($get_impl)* }

                    $(#[$meta])*
                    $(#[$set_meta])*
                    ($($set_args)*) -> $set_type { $($set_impl)* }
                },
            ],
            [$($optional_entries)*],
            [$($rawtail,)*],
            $($tail)*
        }
    };

    // Munch an optional entry
    (@accumulate_entries
        $prefix:tt,
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        [$($req_entries:tt)*],
        [$($optional_entries:tt)*],
        [$raw:ident, $($rawtail:ident,)*],
        $(#[$meta:meta])*
        $entry:ident?: $t:ty,
        $($tail:tt)*
    ) => {
        typed_syscall! {
            @accumulate_entries
            $prefix,
            [$($may_read_entries)*],
            [$($may_written_entries)*],
            [$($req_entries)*],
            [
                $($optional_entries)*
                // Append the munched entry
                {
                    $entry,

                    $(#[$meta])*
                    (&self) -> $t {
                        $crate::FromToRaw::from_raw((self.raw).$raw)
                    }

                    $(#[$meta])*
                    (mut self, v: $t) -> Self {
                        (self.raw).$raw = $crate::FromToRaw::into_raw(v);
                        self
                    }
                },
            ],
            [$($rawtail,)*],
            $($tail)*
        }
    };

    // Munch an optional function entry
    (@accumulate_entries
        $prefix:tt,
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        [$($req_entries:tt)*],
        [$($optional_entries:tt)*],
        [$raw:ident, $($rawtail:ident,)*],
        $(#[$meta:meta])*
        $entry:ident?: {
            $(#[$get_meta:meta])*
            fn get($($get_args:tt)*) -> $get_type:ty { $($get_impl:tt)* }

            $(#[$set_meta:meta])*
            fn set($($set_args:tt)*) -> $set_type:ty { $($set_impl:tt)* }
        },
        $($tail:tt)*
    ) => {
        typed_syscall! {
            @accumulate_entries
            $prefix,
            [$($may_read_entries)*],
            [$($may_written_entries)*],
            [$($req_entries)*],
            [
                $($optional_entries)*
                // Append the munched entry
                {
                    $entry,

                    $(#[$meta])*
                    $(#[$get_meta])*
                    ($($get_args)*) -> $get_type { $($get_impl)* }

                    $(#[$meta])*
                    $(#[$set_meta])*
                    ($($set_args)*) -> $set_type { $($set_impl)* }
                },
            ],
            [$($rawtail,)*],
            $($tail)*
        }
    };

    // Consume #[no_impl_may_read]
    (@accumulate_global_may_rw
        {
            vis: $vis:vis,
            name: $Name:ident,
            attrs: [
                #[no_impl_may_read]
                $(#[$($attrs:tt)*])*
            ],
            ret: $ret:ty,
            impl_may_read: $impl_may_read:ident,
            impl_may_write: $impl_may_write:ident,
            may_read_specified_only: $may_read_specified_only:ident,
            may_write_specified_only: $may_write_specified_only:ident,
        },
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        $($vals:tt)*
    ) => {
        typed_syscall! {
            @accumulate_global_may_rw
            {
                vis: $vis,
                name: $Name,
                attrs: [$(#[$($attrs)*])*],
                ret: $ret,
                impl_may_read: false,
                impl_may_write: $impl_may_write,
                may_read_specified_only: $may_read_specified_only,
                may_write_specified_only: $may_write_specified_only,
            },
            [$($may_read_entries)*],
            [$($may_written_entries)*],
            $($vals)*
        }
    };

    // Consume #[no_impl_may_write]
    (@accumulate_global_may_rw
        {
            vis: $vis:vis,
            name: $Name:ident,
            attrs: [
                #[no_impl_may_write]
                $(#[$($attrs:tt)*])*
            ],
            ret: $ret:ty,
            impl_may_read: $impl_may_read:ident,
            impl_may_write: $impl_may_write:ident,
            may_read_specified_only: $may_read_specified_only:ident,
            may_write_specified_only: $may_write_specified_only:ident,
        },
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        $($vals:tt)*
    ) => {
        typed_syscall! {
            @accumulate_global_may_rw
            {
                vis: $vis,
                name: $Name,
                attrs: [$(#[$($attrs)*])*],
                ret: $ret,
                impl_may_read: $impl_may_read,
                impl_may_write: false,
                may_read_specified_only: $may_read_specified_only,
                may_write_specified_only: $may_write_specified_only,
            },
            [$($may_read_entries)*],
            [$($may_written_entries)*],
            $($vals)*
        }
    };

    // Consume #[may_read_specified_only]
    (@accumulate_global_may_rw
        {
            vis: $vis:vis,
            name: $Name:ident,
            attrs: [
                #[may_read_specified_only]
                $(#[$($attrs:tt)*])*
            ],
            ret: $ret:ty,
            impl_may_read: $impl_may_read:ident,
            impl_may_write: $impl_may_write:ident,
            may_read_specified_only: $may_read_specified_only:ident,
            may_write_specified_only: $may_write_specified_only:ident,
        },
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        $($vals:tt)*
    ) => {
        typed_syscall! {
            @accumulate_global_may_rw
            {
                vis: $vis,
                name: $Name,
                attrs: [$(#[$($attrs)*])*],
                ret: $ret,
                impl_may_read: $impl_may_read,
                impl_may_write: $impl_may_write,
                may_read_specified_only: true,
                may_write_specified_only: $may_write_specified_only,
            },
            [$($may_read_entries)*],
            [$($may_written_entries)*],
            $($vals)*
        }
    };

    // Consume #[may_write_specified_only]
    (@accumulate_global_may_rw
        {
            vis: $vis:vis,
            name: $Name:ident,
            attrs: [
                #[may_write_specified_only]
                $(#[$($attrs:tt)*])*
            ],
            ret: $ret:ty,
            impl_may_read: $impl_may_read:ident,
            impl_may_write: $impl_may_write:ident,
            may_read_specified_only: $may_read_specified_only:ident,
            may_write_specified_only: $may_write_specified_only:ident,
        },
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        $($vals:tt)*
    ) => {
        typed_syscall! {
            @accumulate_global_may_rw
            {
                vis: $vis,
                name: $Name,
                attrs: [$(#[$($attrs)*])*],
                ret: $ret,
                impl_may_read: $impl_may_read,
                impl_may_write: $impl_may_write,
                may_read_specified_only: $may_read_specified_only,
                may_write_specified_only: true,
            },
            [$($may_read_entries)*],
            [$($may_written_entries)*],
            $($vals)*
        }
    };

    (@accumulate_global_may_rw
        $prefix:tt,
        [$($may_read_entries:tt)*],
        [$($may_written_entries:tt)*],
        $($vals:tt)*
    ) => {
        typed_syscall! {
            @accumulate_entries
            $prefix,
            [$($may_read_entries)*],
            [$($may_written_entries)*],
            // List of required entries accumulated thus far.
            [],
            // List of optional entries accumulated thus far.
            [],
            // Queue of raw args. This are popped off in sequence and used for
            // the default implementation of getting and setting raw registers.
            [arg0, arg1, arg2, arg3, arg4, arg5,],
            $($vals)*
        }
    };

    // Entry rule.
    (
        $(#[$($attrs:tt)*])*
        $vis:vis struct $Name:ident -> $ret:ty {
            $($vals:tt)*
        }
    ) => {
        typed_syscall! {
            @accumulate_global_may_rw
            // Meta data that is passed through the munching pipeline until we
            // are ready to generate all of the code.
            {
                vis: $vis,
                name: $Name,
                attrs: [$(#[$($attrs)*])*],
                ret: $ret,
                impl_may_read: true,
                impl_may_write: true,
                may_read_specified_only: false,
                may_write_specified_only: false,
            },
            // List of entries whose pointed target may be read by the syscall.
            [],
            // List of entries whose pointed target may be written by the syscall.
            [],
            // The unprocessed entries, including their metadata.
            $($vals)*
        }
    };

    // Entry rule (with a default return type).
    (
        $(#[$($attrs:tt)*])*
        $vis:vis struct $Name:ident {
            $($vals:tt)*
        }
    ) => {
        typed_syscall! {
            $(#[$($attrs)*])*
            $vis struct $Name -> usize {
                $($vals)*
            }
        }
    };
}

macro_rules! syscall_list {
    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$inner:meta])*
                $num:ident => $item:ident,
            )*
        }
    ) => {
        $(#[$outer])*
        $vis enum $name {
            $(
                $(#[$inner])*
                $item($item),
            )*

            /// Catch-all for syscalls that are not yet type-safe.
            Other(::syscalls::Sysno, ::syscalls::SyscallArgs),
        }

        impl $name {
            /// Creates a `Syscall` from raw arguments. If the specified syscall
            /// is not supported, a `Syscall::Other` will be created.
            pub fn from_raw(syscall: ::syscalls::Sysno, args: ::syscalls::SyscallArgs) -> Self {
                match syscall {
                    $(
                        $(#[$inner])*
                        ::syscalls::Sysno::$num => $name::$item(args.into()),
                    )*
                    num => Syscall::Other(num, args),
                }
            }
        }

        impl $crate::SyscallInfo for $name {
            type Return = Result<usize, $crate::Errno>;

            fn name(&self) -> &'static str {
                match self {
                    $(
                        $(#[$inner])*
                        $name::$item(_) => $item::NAME,
                    )*
                    $name::Other(syscall, _) => syscall.name(),
                }
            }

            fn number(&self) -> ::syscalls::Sysno {
                match self {
                    $(
                        $(#[$inner])*
                        $name::$item(_) => ::syscalls::Sysno::$num,
                    )*
                    $name::Other(num, _) => *num,
                }
            }

            fn into_parts(self) -> (::syscalls::Sysno, ::syscalls::SyscallArgs) {
                match self {
                    $(
                        $(#[$inner])*
                        $name::$item(x) => (::syscalls::Sysno::$num, x.into()),
                    )*
                    $name::Other(num, args) => (num, args),
                }
            }
        }

        impl<'a, M: MemoryAccess> $crate::syscalls::may_rw::SyscallMayRead<'a, M> for $name {
            fn may_read(&'a self, memory: &'a M) -> Result<Box<[::reverie_memory::AddrSlice<'a, u8>]>, $crate::Errno> {
                match self {
                    $(
                        $(#[$inner])*
                        $name::$item(x) => x.may_read(memory),
                    )*
                    $name::Other(_num, _args) => $crate::syscalls::may_rw::RangesSyscallMayReadBuilder::new(memory).may_read_anything().build(),
                }
            }
        }

        impl<'a, M: MemoryAccess> $crate::syscalls::may_rw::SyscallMayWrite<'a, M> for $name {
            fn may_write(&'a self, memory: &'a M) -> Result<Box<[::reverie_memory::AddrSliceMut<'a, u8>]>, $crate::Errno> {
                match self {
                    $(
                        $(#[$inner])*
                        $name::$item(x) => x.may_write(memory),
                    )*
                    $name::Other(_num, _args) => $crate::syscalls::may_rw::RangesSyscallMayWriteBuilder::new(memory).may_write_anything().build(),
                }
            }
        }

        $(
            $(#[$inner])*
            impl From<$item> for $name {
                fn from(x: $item) -> Self {
                    $name::$item(x)
                }
            }
        )*

        impl $crate::Displayable for $name {
            fn fmt<M: $crate::MemoryAccess>(
                &self,
                memory: &M,
                outputs: bool,
                f: &mut ::core::fmt::Formatter,
            ) -> ::core::fmt::Result {
                match self {
                    $(
                        $(#[$inner])*
                        $name::$item(x) => $crate::Displayable::fmt(x, memory, outputs, f),
                    )*
                    $name::Other(num, args) => {
                        // Write out the raw arguments.
                        write!(
                            f,
                            "{:?}({}, {}, {}, {}, {}, {})",
                            num,
                            args.arg0,
                            args.arg1,
                            args.arg2,
                            args.arg3,
                            args.arg4,
                            args.arg5
                        )
                    }
                }
            }
        }
    };
}

/// Generate code for fcntl-like enums where there is a code specifying the
/// command and a value associated with the command.
macro_rules! command_enum {
    // Exit rule
    (@emit_enum
        {
            vis: $vis:vis,
            name: $name:ident,
            lifetimes: [$($lt:lifetime,)*],
            attrs: [$(#[$attrs:meta])*],
            type: $type:ty,
            entries: [$({
                meta: [$(#[$meta:meta])*],
                id: $id:expr,
                flag: $flag:ident,
                into: $(($arg:ident: $t:ty))? => $raw:expr,
            },)*],
        }
    ) => {
        $(#[$attrs])*
        #[allow(non_camel_case_types, clippy::upper_case_acronyms)]
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        $vis enum $name<$($lt,)*> {
            $(
                #[allow(missing_docs)]
                $(#[$meta])*
                $flag$(($t))?,
            )*

            /// Catch-all case when we don't know the command and its argument.
            Other($type, usize),
        }

        impl<$($lt,)*> ::core::fmt::Display for $name<$($lt,)*> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                // Same as derived debug
                <Self as ::core::fmt::Debug>::fmt(self, f)
            }
        }

        impl<$($lt,)*> $crate::Displayable for $name<$($lt,)*> {
            fn fmt<M: $crate::MemoryAccess>(
                &self,
                memory: &M,
                outputs: bool,
                f: &mut ::core::fmt::Formatter,
            ) -> ::core::fmt::Result {
                match self {
                    $(
                        $(#[$meta])*
                        $name::$flag$(($arg))? => {
                            f.write_str(stringify!($flag))?;
                            $(
                                f.write_str(", ")?;
                                $crate::Displayable::fmt($arg, memory, outputs, f)?;
                            )?
                            Ok(())
                        }
                    )*
                    $name::Other(cmd, arg) => write!(f, "{}, {:#x}", cmd, arg),
                }
            }
        }

        impl<$($lt,)*> $name<$($lt,)*> {
            /// Creates the enum from raw arguments.
            pub fn from_raw(cmd: $type, arg: usize) -> Self {
                match cmd {
                    $(
                        $(#[$meta])*
                        $id => $name::$flag$((<$t as $crate::FromToRaw>::from_raw(arg)))?,
                    )*
                    _ => $name::Other(cmd, arg),
                }
            }

            /// Converts the enum into raw arguments.
            pub fn into_raw(self) -> ($type, usize) {
                match self {
                    $(
                        $(#[$meta])*
                        $name::$flag$(($arg))? => ($id, $raw),
                    )*
                    $name::Other(cmd, arg) => (cmd, arg),
                }
            }
        }
    };

    // Done collecting entries
    (@collect_entries
        {
            $($prefix:tt)*
        },
        [$($entries:tt)*],
    ) => {
        command_enum! {
            @emit_enum
            {
                $($prefix)*
                entries: [$($entries)*],
            }
        }
    };

    // Collect an entry with a single argument.
    (@collect_entries
        $prefix:tt,
        [$($entries:tt)*],
        $(#[$meta:meta])*
        $flag:ident($t:ty) = $id:expr,
        $($tail:tt)*
    ) => {
        command_enum! {
            @collect_entries
            $prefix,
            [
                $($entries)*
                {
                    meta: [$(#[$meta])*],
                    id: $id,
                    flag: $flag,
                    into: (arg: $t) => arg.into_raw(),
                },
            ],
            $($tail)*
        }
    };

    // Collect an entry with zero arguments.
    (@collect_entries
        $prefix:tt,
        [$($entries:tt)*],
        $(#[$meta:meta])*
        $flag:ident = $id:expr,
        $($tail:tt)*
    ) => {
        command_enum! {
            @collect_entries
            $prefix,
            [
                $($entries)*
                {
                    meta: [$(#[$meta])*],
                    id: $id,
                    flag: $flag,
                    into: => 0,
                },
            ],
            $($tail)*
        }
    };

    // Entry rule
    (
        $(#[$attrs:meta])*
        $vis:vis enum $name:ident$(<$($lt:lifetime),*>)?: $t:ty {
            $($entries:tt)*
        }
    ) => {
        command_enum! {
            @collect_entries
            {
                vis: $vis,
                name: $name,
                lifetimes: [$($($lt,)*)?],
                attrs: [$(#[$attrs])*],
                type: $t,
            },
            [],
            $($entries)*
        }
    };
}

// Helper for generating an enum-like struct. This helps to avoid casting raw
// integers to an `enum`, which may result in undefined behavior if the integer
// does not match any of the enum variants.
//
// Note that the item must have a matching definition in `libc`.
macro_rules! const_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $Name:ident : $inner:ident {
            $(
                $(#[$attrs:meta])*
                $item:ident,
            )*
        }
    ) => {
        $(#[$meta])*
        $vis struct $Name($inner);

        impl $Name {
            $(
                $(#[$attrs])*
                #[allow(missing_docs)]
                pub const $item: $Name = Self(libc::$item);
            )*
        }

        impl $crate::FromToRaw for $Name {
            fn from_raw(raw: usize) -> Self {
                Self(raw as $inner)
            }

            fn into_raw(self) -> usize {
                self.0 as usize
            }
        }

        impl $crate::Displayable for $Name {
            fn fmt<M: $crate::MemoryAccess>(
                &self,
                _memory: &M,
                _outputs: bool,
                f: &mut ::core::fmt::Formatter,
            ) -> ::core::fmt::Result {
                match *self {
                    $(
                        Self::$item => f.write_str(stringify!($item)),
                    )*
                    Self(x) => write!(f, "{:#x}", x),
                }
            }
        }
    };
}
