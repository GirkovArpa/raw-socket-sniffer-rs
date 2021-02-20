extern crate winapi;
extern crate libc;

// We use defines and structures copied from libpcap to synthesize a PCAP file.
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;

const DLT_EN10MB: u32 = 1;

struct pcap_timeval {
    tv_sec: i32,
    tv_usec: i32,
}

struct pcap_file_header {
    magic: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    linktype: u32
}

struct pcap_sf_pkthdr {
    ts: pcap_timeval,
    caplen: u32,
    len: u32
}

// Various sizes and offsets for our packet read buffer.
const BUFFER_SIZE_HDR: u32 = std::mem::size_of::<pcap_sf_pkthdr>() as u32;
const BUFFER_SIZE_PKT: u32 = (256 * 256) - 1;
const BUFFER_SIZE_ETH: u32 = 14;
const BUFFER_SIZE_IP: u32 = BUFFER_SIZE_PKT - BUFFER_SIZE_ETH;
const BUFFER_OFFSET_ETH: u32 = std::mem::size_of::<pcap_sf_pkthdr>() as u32;
const BUFFER_OFFSET_IP: u32 = BUFFER_OFFSET_ETH + BUFFER_SIZE_ETH;

// A couple of defines used to calculate high resolution timestamps.
const EPOCH_BIAS: i64 = 116444736000000000;
const UNITS_PER_SEC: i32 = 10000000;

// Normally we would break this up into smaller functions, but here we lay out
// all the steps to capture packets using raw sockets one step after another.
fn main() -> () {
  let argv: Vec<String> = std::env::args().collect();
  let argc = argv.len();

  if argc != 3 {
      eprintln!("usage: {} <interface-ip> <capture-file>", argv[0]);
      std::process::exit(-1);
  }

  // Windows winsock requires this.
  unsafe {
    let mut wsa_data = std::mem::MaybeUninit::<winapi::um::winsock2::WSADATA>::zeroed();
    winapi::um::winsock2::WSAStartup(
      winapi::shared::minwindef::MAKEWORD(2, 2), 
      wsa_data.as_mut_ptr()
    );
  }

    // Open our capture file, overwrite if it already exists.
    let fp = unsafe { 
      libc::fopen(argv[2].as_ptr() as *const i8, "wb".as_ptr()  as *const i8) 
    };
    if fp.is_null() {
        eprintln!("fopen({:?}) failed: {:?}", argv[2], std::io::Error::last_os_error().raw_os_error());
        std::process::exit(-1);
    }

    // Disable file buffering to prevent file corruption on termination.
    unsafe { 
      libc::setbuf(fp, std::ptr::null_mut());
    };

    // Create a PCAP file header.
    let hdr = pcap_file_header {
      magic: 0xa1b2c3d4,
      version_major: PCAP_VERSION_MAJOR,
      version_minor: PCAP_VERSION_MINOR,
      thiszone: 0,
      snaplen: BUFFER_SIZE_PKT,
      sigfigs: 0,
      linktype: DLT_EN10MB,
    };

    // Write the PCAP file header to our capture file.
    unsafe {
      if libc::fwrite(std::ptr::null(), std::mem::size_of::<pcap_file_header>(), 1, fp) != 1 {
          eprintln!("fwrite(pcap_file_header) failed: {:?}", std::io::Error::last_os_error().raw_os_error());
          std::process::exit(-1);
      }
    }

    // Create a raw socket which supports IPv4 only.
    let sd = unsafe {
      winapi::um::winsock2::socket(winapi::shared::ws2def::AF_INET, winapi::shared::ws2def::SOCK_RAW, winapi::shared::ws2def::IPPROTO_IP) 
    };

    if sd == winapi::um::winsock2::INVALID_SOCKET {
      unsafe {
        eprintln!("socket() failed: {:?}", winapi::um::winsock2::WSAGetLastError());
      }
      std::process::exit(-1);
    }

    // Captured IP packets sent and received by the network interface the
    // specified IP address is associated with.

    // cannot construct `in_addr_S_un` with struct literal syntax due to inaccessible fields 
    let in_addr_S_un = winapi::shared::inaddr::in_addr_S_un {};

    let in_addr = winapi::shared::inaddr::IN_ADDR {
      S_un: in_addr_S_un
    };

    let addr = winapi::shared::ws2def::SOCKADDR_IN {
      sin_family: winapi::shared::ws2def::AF_INET as u16,
      sin_port: unsafe { winapi::um::winsock2::htons(0) },
      sin_addr: in_addr,
      sin_zero: [ 1, 2, 3, 4, 5, 6, 7, 8 ]
    };

}