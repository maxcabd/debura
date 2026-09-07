use std::fmt;

use serde::{Deserialize, Serialize};

macro_rules! define_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub struct $name(pub u64);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, self.0)
            }
        }
    };
}

define_id!(ObservationId, "O");
define_id!(EvidenceId, "E");
define_id!(HypothesisId, "H");
define_id!(InvestigationId, "I");
