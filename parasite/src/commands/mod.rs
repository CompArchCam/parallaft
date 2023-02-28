pub mod hello;
pub mod verify;

use self::hello::Hello;
use self::verify::Verify;

pub trait Command {
    type Request;
    type Response;

    fn execute(cmd: &Self::Request) -> Self::Response;
}

macro_rules! command_list {
    ( $( $x:ident ),* ) => {
        #[derive(Clone, Copy, Debug)]
        pub enum Request {
            $(
                $x(<$x as Command>::Request),
            )*
        }

        #[derive(Clone, Copy, Debug)]
        pub enum Response {
            $(
                $x(<$x as Command>::Response),
            )*
        }

        pub fn handle_request(req: &Request) -> Response {
            match req {
                $(
                    Request::$x(req) => Response::$x($x::execute(req)),
                )*
            }
        }
    };
}

#[macro_export]
macro_rules! call_remote {
    ($ctl:expr,$x:ident,$req:expr) => {
        $ctl.rpc_call_sync_ret(0, $crate::commands::Request::$x($req))
            .map(|res| {
                if let $crate::commands::Response::$x(res) = res {
                    res
                } else {
                    panic!("unexpected response")
                }
            })
    };
}

command_list![Hello, Verify];
