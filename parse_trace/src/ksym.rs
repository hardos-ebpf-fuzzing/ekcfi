use std::cmp::Ordering;
use std::fmt;
use std::fs::read_to_string;

#[derive(Debug, Copy, Clone)]
pub enum KsymType {
    Abs,
    Bss,
    Data,
    RonlyData,
    Text,
    Weak,
}

impl TryFrom<char> for KsymType {
    type Error = &'static str;
    fn try_from(value: char) -> Result<Self, Self::Error> {
        match value {
            'A' | 'a' => Ok(Self::Abs),
            'B' | 'b' => Ok(Self::Bss),
            'D' | 'd' => Ok(Self::Data),
            'R' | 'r' => Ok(Self::RonlyData),
            'T' | 't' => Ok(Self::Text),
            'W' | 'V' => Ok(Self::Weak),
            _ => Err("Unsupported symbol type {}"),
        }
    }
}

impl From<KsymType> for char {
    fn from(value: KsymType) -> Self {
        match value {
            KsymType::Abs => 'A',
            KsymType::Bss => 'B',
            KsymType::Data => 'D',
            KsymType::RonlyData => 'R',
            KsymType::Text => 'T',
            KsymType::Weak => 'W',
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ksym {
    base_addr: u64,
    ty: KsymType,
    name: String,
}

impl Ksym {
    #[inline(always)]
    pub fn new(base_addr: u64, ty: KsymType, name: &str) -> Self {
        Self {
            base_addr,
            ty,
            name: name.to_string(),
        }
    }

    #[inline(always)]
    pub fn is_pf_handler(&self) -> bool {
        self.name == "do_fault"
    }

    #[inline(always)]
    pub fn is_syscall_entry(&self) -> bool {
        self.name == "do_syscall_64"
    }

    #[inline(always)]
    pub fn get_base_addr(&self) -> u64 {
        self.base_addr
    }

    #[inline(always)]
    #[allow(unused)]
    pub fn get_type(&self) -> KsymType {
        self.ty
    }

    #[inline(always)]
    pub fn get_name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for Ksym {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({:#x}, {}, {})",
            self.base_addr,
            <char as From<KsymType>>::from(self.ty),
            self.name
        )
    }
}

impl Ord for Ksym {
    fn cmp(&self, other: &Self) -> Ordering {
        self.base_addr.cmp(&other.base_addr)
    }
}

impl PartialOrd for Ksym {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Ksym {
    fn eq(&self, other: &Self) -> bool {
        self.base_addr == other.base_addr
    }
}

impl Eq for Ksym {}

pub fn parse_ksym(line: &str) -> Result<Ksym, &'static str> {
    let mut iter = line.split_whitespace();
    let addr_str = iter.next().ok_or("invalid syntex in System.map")?;
    let ty_str = iter.next().ok_or("invalid syntex in System.map")?;
    let name = iter.next().ok_or("invalid syntex in System.map")?;
    let addr =
        u64::from_str_radix(addr_str, 16).map_err(|_| "invalid address syntex in System.map")?;
    let ty = ty_str
        .chars()
        .nth(0)
        .map_or(Err("invalid symbol syntex in System.map"), |c| {
            <KsymType as TryFrom<char>>::try_from(c)
        })?;
    Ok(Ksym::new(addr, ty, name))
}

pub fn parse_system_map(filename: &str) -> Result<Vec<Ksym>, &'static str> {
    let mut result = Vec::new();

    for line in read_to_string(filename)
        .map_err(|_| "failed to read System.map")?
        .lines()
    {
        result.push(parse_ksym(line)?);
    }

    Ok(result)
}
