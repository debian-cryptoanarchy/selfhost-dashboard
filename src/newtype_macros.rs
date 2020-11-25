macro_rules! token_newtype {
    ($name:ident, $len:expr, $error_name:ident) => {
        #[allow(clippy::derive_hash_xor_eq)] // fine because our impl satisfies the required property
        #[derive(Debug, Copy, Clone, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String")]
        pub struct $name([u8; $len]);

        impl $name {
            #[allow(unused)]
            pub fn random() -> Self {
                $name(rand::random())
            }
        }

        impl core::cmp::PartialEq for $name {
            /// Compares in constant time
            fn eq(&self, other: &$name) -> bool {
                self
                    .0
                    .iter()
                    .zip(&other.0)
                    .map(|(a, b)| (a != b) as usize)
                    .sum::<usize>() == 0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                for b in &self.0 {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }

        impl slog::Value for $name {
            fn serialize(&self, _record: &slog::Record, key: slog::Key, serializer: &mut dyn slog::Serializer) -> slog::Result {
                for b in &self.0 {
                    serializer.emit_arguments(key, &format_args!("{:02x}", b))?;
                }
                Ok(())
            }
        }

        impl core::str::FromStr for $name {
            type Err = $error_name;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                use $crate::hex::FromHex;

                FromHex::from_hex(value)
                    .map($name)
                    .map_err($error_name)
            }
        }

        impl<'a> core::convert::TryFrom<&'a str> for $name {
            type Error = $error_name;

            fn try_from(value: &'a str) -> Result<Self, Self::Error> {
                value.parse()
            }
        }

        impl core::convert::TryFrom<String> for $name {
            type Error = $error_name;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                value.parse()
            }
        }

        #[derive(Debug, thiserror::Error)]
        #[error(transparent)]
        pub struct $error_name(hex::FromHexError);

        impl tokio_postgres::types::ToSql for $name {
            fn to_sql(&self, ty: &tokio_postgres::types::Type, out: &mut tokio_postgres::types::private::BytesMut) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + 'static + Sync + Send>> {
                (&(self.0) as &[u8]).to_sql(ty, out)
            }

            fn accepts(ty: &tokio_postgres::types::Type) -> bool {
                <&[u8]>::accepts(ty)
            }


            fn to_sql_checked(&self, ty: &tokio_postgres::types::Type, out: &mut tokio_postgres::types::private::BytesMut) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + 'static + Sync + Send>> {
                (&(self.0) as &[u8]).to_sql_checked(ty, out)
            }
        }

        impl<'a> tokio_postgres::types::FromSql<'a> for $name {
            fn from_sql(ty: &tokio_postgres::types::Type, raw: &'a [u8]) -> Result<Self, Box<dyn std::error::Error + 'static + Sync + Send>> {
                use core::convert::TryInto;

                let &arr = <&'a [u8]>::from_sql(ty, raw)?
                    .try_into()
                    .map_err(Box::new)?;
                Ok(Self(arr))
            }

            fn accepts(ty: &tokio_postgres::types::Type) -> bool {
                <&'a [u8]>::accepts(ty)
            }
        }
    }
}

macro_rules! str_validation_newtype {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Hash)]
        pub struct $name<S = String>(S) where S: $crate::primitives::Stringly;

        impl<S> $name<S> where S: $crate::primitives::Stringly {
            #[allow(unused)]
            pub fn into_inner(self) -> S {
                self.0
            }

            #[allow(unused)]
            pub fn as_ref(&self) -> $name<&str> {
                $name(self.0.as_ref())
            }

            #[allow(unused)]
            pub fn into_owned(self) -> $name<String> {
                $name(self.0.as_ref().into())
            }
        }

        impl<S> core::borrow::Borrow<str> for $name<S> where S: $crate::primitives::Stringly {
            fn borrow(&self) -> &str {
                self.0.borrow()
            }
        }

        impl<S> core::fmt::Display for $name<S> where S: $crate::primitives::Stringly {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.0, f)
            }
        }

        impl<S> slog::Value for $name<S> where S: $crate::primitives::Stringly {
            fn serialize(&self, _record: &slog::Record, key: slog::Key, serializer: &mut dyn slog::Serializer) -> slog::Result {
                serializer.emit_str(key, self.0.as_ref())
            }
        }

        impl<S> core::ops::Deref for $name<S> where S: $crate::primitives::Stringly {
            type Target = str;

            fn deref<'a>(&'a self) -> &'a Self::Target {
                self.0.borrow()
            }
        }

        impl<S> tokio_postgres::types::ToSql for $name<S> where S: $crate::primitives::Stringly {
            fn to_sql(&self, ty: &tokio_postgres::types::Type, out: &mut tokio_postgres::types::private::BytesMut) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + 'static + Sync + Send>> {
                self.0.as_ref().to_sql(ty, out)
            }

            fn accepts(ty: &tokio_postgres::types::Type) -> bool {
                <&str>::accepts(ty)
            }


            fn to_sql_checked(&self, ty: &tokio_postgres::types::Type, out: &mut tokio_postgres::types::private::BytesMut) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + 'static + Sync + Send>> {
                self.0.borrow().to_sql_checked(ty, out)
            }
        }

        impl<'a, S, E> tokio_postgres::types::FromSql<'a> for $name<S> where S: $crate::primitives::Stringly + core::convert::TryInto<$name<S>, Error=E> + tokio_postgres::types::FromSql<'a>, E: 'static + std::error::Error + Sync + Send {
            fn from_sql(ty: &tokio_postgres::types::Type, raw: &'a [u8]) -> Result<Self, Box<dyn std::error::Error + 'static + Sync + Send>> {
                #[allow(unused)]
                use std::convert::TryInto;

                Ok(S::from_sql(ty, raw)?.try_into()?)
            }

            fn accepts(ty: &tokio_postgres::types::Type) -> bool {
                <S>::accepts(ty)
            }
        }
    };
}

macro_rules! str_char_whitelist_newtype {
    ($name:ident, $error_name:ident, $what:expr, $validation_fn:expr) => {
        str_validation_newtype!($name);

        #[derive(Debug, Clone, thiserror::Error)]
        #[error("invalid {} {string}: forbidden character '{c}' at position {position}", $what)]
        pub struct $error_name {
            string: String,
            c: char,
            position: usize,
        }

        impl core::convert::TryFrom<String> for $name<String> {
            type Error = $error_name;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                match value.chars().enumerate().find(|&(_, c)| (($validation_fn))(c)) {
                    None => Ok($name(value)),
                    Some((position, c)) => Err($error_name {
                        string: value.into(),
                        c,
                        position,
                    })
                }
            }
        }

        impl<'a> core::convert::TryFrom<&'a str> for $name<&'a str> {
            type Error = $error_name;

            fn try_from(value: &'a str) -> Result<Self, Self::Error> {
                match value.chars().enumerate().find(|&(_, c)| (($validation_fn))(c)) {
                    None => Ok($name(value)),
                    Some((position, c)) => Err($error_name {
                        string: value.into(),
                        c,
                        position,
                    })
                }
            }
        }

        /*
        impl<S> core::convert::TryFrom<S> for $name<S> where S: $crate::primitives::Stringly {
            type Error = $error_name;

            fn try_from(value: S) -> Result<Self, Self::Error> {
                match value.chars().enumerate().find(|&(_, c)| ($validation_fn)(c)) {
                    None => Ok(value),
                    Some((position, c)) => Err($error_name {
                        string: value.into(),
                        c,
                        position,
                    })
                }
            }
        }
        */
    };
}

#[cfg(test)]
macro_rules! test_str_val_ok {
    ($test_name:ident, $type:ident, $string:expr) => {
        #[test]
        fn $test_name() {
            use core::convert::TryFrom;

            <$type<&str>>::try_from($string).unwrap();
        }
    };
}

#[cfg(test)]
macro_rules! test_str_val_err {
    ($test_name:ident, $type:ident, $string:expr) => {
        #[test]
        fn $test_name() {
            use core::convert::TryFrom;

            assert!(<$type<&str>>::try_from($string).is_err());
        }
    };
}
