//===
// by xolokram/TB
// 2013
//===

#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <map>

#include "main.h"
#include "serialize.h"
#include "bitcoinrpc.h"
#include "json/json_spirit_value.h"
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/uuid/sha1.hpp>

#define VERSION_MAJOR 0
#define VERSION_MINOR 1
#define VERSION_EXT "Beta"

#define MAX_THREADS 32

// <START> be compatible to original code (not actually used!)
#include "txdb.h"
#include "walletdb.h"
#include "wallet.h"
#include "ui_interface.h"
CWallet *pwalletMain;
CClientUIInterface uiInterface;
void StartShutdown() {
  exit(0);
}
// </END>

/*********************************
* global variables, structs and extern functions
*********************************/

extern CBlockIndex *pindexBest;
extern uint256 nShareBits;
uint256 nNetworkBits = 0;
extern void BitcoinMiner(CWallet        *pwallet,
                         CBlockProvider *CBlockProvider,
                         unsigned int thread_id);
extern bool fPrintToConsole;
extern bool fDebug;

struct blockHeader_t {
  // comments: BYTES <index> + <length>
  int           nVersion;            // 0+4
  uint256       hashPrevBlock;       // 4+32
  uint256       hashMerkleRoot;      // 36+32
  unsigned int  nTime;               // 68+4
  unsigned int  nBits;               // 72+4
  unsigned int  nNonce;              // 76+4
  unsigned int  nBirthdayA;          // 80+4
  unsigned int  nBirthdayB;          // 84+4                                 /
};                                   // = 88 bytes header (80 default + 48 primemultiplier)

size_t thread_num_max;
static size_t fee_to_pay;
static size_t miner_id;
static boost::asio::ip::tcp::socket* socket_to_server;
static boost::posix_time::ptime t_start;
static std::map<int,unsigned long> statistics;
static bool running;
static volatile int submitting_share;
std::string pool_username;
std::string pool_password;

/*********************************
* helping functions
*********************************/

void convertDataToBlock(unsigned char* blockData, CBlock& block) {
  {
    std::stringstream ss;
    for (int i = 7; i >= 0; --i)
		ss << std::setw(8) << std::setfill('0') << std::hex << *((int *)(blockData + 4) + i);
    ss.flush();
    block.hashPrevBlock.SetHex(ss.str().c_str());
  }
  {
    std::stringstream ss;
    for (int i = 7; i >= 0; --i)
		ss << std::setw(8) << std::setfill('0') << std::hex << *((int *)(blockData + 36) + i);
    ss.flush();
    block.hashMerkleRoot.SetHex(ss.str().c_str());
  }
  {
    std::stringstream ss;
    for (int i = 7; i >= 0; --i)
		ss << std::setw(8) << std::setfill('0') << std::hex << *((int *)(blockData + 80) + i);
    ss.flush();
    //block.hashMerkleRoot.SetHex(ss.str().c_str());
    nShareBits.SetHex(ss.str().c_str());
  }
  block.nVersion               = *((int *)(blockData));
  block.nTime                  = *((unsigned int *)(blockData + 68));
  block.nBits                  = *((unsigned int *)(blockData + 72));
  block.nNonce                 = *((unsigned int *)(blockData + 76));
  block.nBirthdayA = 0;
  block.nBirthdayB = 0;


  nNetworkBits = CBigNum().SetCompact(block.nBits).getuint256();

  //nShareBits =  *((unsigned int *)(blockData + 80));

  //nShareBits = CBigNum().SetHex(*((unsigned char *)(blockData + 80))).GetCompact();
}

/*********************************
* class CBlockProviderGW to (incl. SUBMIT_BLOCK)
*********************************/

class CBlockProviderGW : public CBlockProvider {
public:

	CBlockProviderGW() : CBlockProvider(), nTime_offset(0), _blocks(NULL) {}

	virtual ~CBlockProviderGW() { /* TODO */ }

	virtual unsigned int GetAdjustedTimeWithOffset(unsigned int thread_id) {
		return nTime_offset + ((((unsigned int)GetAdjustedTime() + thread_num_max) / thread_num_max) * thread_num_max) + thread_id;
	}

	virtual CBlock* getBlock(unsigned int thread_id, unsigned int last_time) {
		boost::unique_lock<boost::shared_mutex> lock(_mutex_getwork);
		if (_blocks == NULL) return NULL;
		CBlock* block = NULL;
		block = new CBlock(_blocks->GetBlockHeader());
		unsigned int new_time = GetAdjustedTimeWithOffset(thread_id);
		if (new_time == last_time)
			new_time += thread_num_max;
		block->nTime = new_time; //TODO: check if this is the same time like before!?
		//std::cout << "[WORKER" << thread_id << "] got_work block=" << block->GetHash().ToString().c_str() << std::endl;
		return block;
	}

	void setBlocksFromData(unsigned char* data) {
		CBlock* blocks = new CBlock(); //[thread_num_count];
		//for (size_t i = 0; i < thread_num_count; ++i)
		//	convertDataToBlock(data+i*128,blocks[i]);
		convertDataToBlock(data,*blocks);
		//
		unsigned int nTime_local = GetAdjustedTime();
		unsigned int nTime_server = blocks->nTime;
		nTime_offset = nTime_local > nTime_server ? 0 : (nTime_server-nTime_local);
		//
		CBlock* old_blocks = NULL;
		{
			boost::unique_lock<boost::shared_mutex> lock(_mutex_getwork);
			old_blocks = _blocks;
			_blocks = blocks;
		}
		if (old_blocks != NULL) delete old_blocks;
	}

	void submitBlock(CBlock *block) {
		blockHeader_t blockraw;
		blockraw.nVersion       = block->nVersion;
		blockraw.hashPrevBlock  = block->hashPrevBlock;
		blockraw.hashMerkleRoot = block->hashMerkleRoot;
		blockraw.nTime          = block->nTime;
		blockraw.nBits          = block->nBits;
		blockraw.nNonce         = block->nNonce;
		blockraw.nBirthdayA     = block->nBirthdayA;
        blockraw.nBirthdayB     = block->nBirthdayB;
		//std::cout << "submit: " << block->hashMerkleRoot.ToString().c_str() << std::endl;


		boost::posix_time::ptime submit_start = boost::posix_time::second_clock::universal_time();
		boost::system::error_code submit_error = boost::asio::error::host_not_found; //run at least 1 time
		++submitting_share;
		while (submit_error && running && (boost::posix_time::second_clock::universal_time() - submit_start).total_seconds() < 80) {
			while (socket_to_server == NULL && running && (boost::posix_time::second_clock::universal_time() - submit_start).total_seconds() < 80) //socket error was issued somewhere else
				boost::this_thread::sleep(boost::posix_time::milliseconds(100));
			if (running && (boost::posix_time::second_clock::universal_time() - submit_start).total_seconds() < 80) {
				boost::asio::write(*socket_to_server, boost::asio::buffer((unsigned char*)&blockraw, 88), boost::asio::transfer_at_least(1), submit_error); //FaF
				//size_t len = boost::asio::write(*socket_to_server, boost::asio::buffer((unsigned char*)&blockraw, 128), boost::asio::transfer_all(), submit_error);
				//socket_to_server->write_some(boost::asio::buffer((unsigned char*)&blockraw, 128), submit_error);
				//if (submit_error)
				//	std::cout << submit_error << " @ write_submit" << std::endl;
			}
		}
		--submitting_share;
	}

	void forceReconnect() {
		std::cout << "force reconnect if possible!" << std::endl;
		if (socket_to_server != NULL) {
			boost::system::error_code close_error;
			socket_to_server->close(close_error);
			//if (close_error)
			//	std::cout << close_error << " @ close" << std::endl;
		}
	}

protected:
	unsigned int nTime_offset;
	boost::shared_mutex _mutex_getwork;
	CBlock* _blocks;
};

/*********************************
* multi-threading
*********************************/

class CMasterThreadStub {
public:
  virtual void wait_for_master() = 0;
  virtual boost::shared_mutex& get_working_lock() = 0;
};

class CWorkerThread { // worker=miner
public:

	CWorkerThread(CMasterThreadStub *master, unsigned int id, CBlockProviderGW *bprovider)
		: _working_lock(NULL), _id(id), _master(master), _bprovider(bprovider), _thread(&CWorkerThread::run, this) { }

	void run() {
		std::cout << "[WORKER" << _id << "] Hello, World!" << std::endl;
		_master->wait_for_master();
		std::cout << "[WORKER" << _id << "] GoGoGo!" << std::endl;
		boost::this_thread::sleep(boost::posix_time::seconds(2));
		BitcoinMiner(NULL, _bprovider, _id);
		std::cout << "[WORKER" << _id << "] Bye Bye!" << std::endl;
	}

	void work() { // called from within master thread
		_working_lock = new boost::shared_lock<boost::shared_mutex>(_master->get_working_lock());
	}

protected:
  boost::shared_lock<boost::shared_mutex> *_working_lock;
  unsigned int _id;
  CMasterThreadStub *_master;
  CBlockProviderGW  *_bprovider;
  boost::thread _thread;
};

class CMasterThread : public CMasterThreadStub {
public:

  CMasterThread(CBlockProviderGW *bprovider) : CMasterThreadStub(), _bprovider(bprovider) {}

  void run() {

	{
		boost::unique_lock<boost::shared_mutex> lock(_mutex_master);
		std::cout << "spawning " << thread_num_max << " worker thread(s)" << std::endl;

		for (unsigned int i = 0; i < thread_num_max; ++i) {
			CWorkerThread *worker = new CWorkerThread(this, i, _bprovider);
			worker->work();
		}
	}

    boost::asio::io_service io_service;
    boost::asio::ip::tcp::resolver resolver(io_service); //resolve dns
    boost::asio::ip::tcp::resolver::query query(GetArg("-poolip", "127.0.0.1"), GetArg("-poolport", "1337"));
    boost::asio::ip::tcp::resolver::iterator endpoint;
	boost::asio::ip::tcp::resolver::iterator end;
	boost::asio::ip::tcp::no_delay nd_option(true);
	boost::asio::socket_base::keep_alive ka_option(true);

	while (running) {
		endpoint = resolver.resolve(query);
		boost::scoped_ptr<boost::asio::ip::tcp::socket> socket;
		boost::system::error_code error_socket = boost::asio::error::host_not_found;
		while (error_socket && endpoint != end)
		{
		  //socket->close();
		  socket.reset(new boost::asio::ip::tcp::socket(io_service));
		  boost::asio::ip::tcp::endpoint tcp_ep = *endpoint++;
		  socket->connect(tcp_ep, error_socket);
		  std::cout << "connecting to " << tcp_ep << std::endl;
		}
		socket->set_option(nd_option);
		socket->set_option(ka_option);

		if (error_socket) {
			std::cout << error_socket << std::endl;
			boost::this_thread::sleep(boost::posix_time::seconds(10));
			continue;
		}

		{ //send hello message
			char* hello = new char[pool_username.length()+/*v0.2/0.3=*/2+/*v0.4=*/20+/*v0.7=*/1+pool_password.length()];
			memcpy(hello+1, pool_username.c_str(), pool_username.length());
			*((unsigned char*)hello) = pool_username.length();
			*((unsigned char*)(hello+pool_username.length()+1)) = 0; //hi, i'm v0.4+
			*((unsigned char*)(hello+pool_username.length()+2)) = VERSION_MAJOR;
			*((unsigned char*)(hello+pool_username.length()+3)) = VERSION_MINOR;
			*((unsigned char*)(hello+pool_username.length()+4)) = thread_num_max;
			*((unsigned char*)(hello+pool_username.length()+5)) = fee_to_pay;
			*((unsigned short*)(hello+pool_username.length()+6)) = miner_id;
			*((unsigned int*)(hello+pool_username.length()+8)) = 0;
			*((unsigned int*)(hello+pool_username.length()+12)) = 0;
			*((unsigned int*)(hello+pool_username.length()+16)) = 0;
			*((unsigned char*)(hello+pool_username.length()+20)) = pool_password.length();
			memcpy(hello+pool_username.length()+21, pool_password.c_str(), pool_password.length());
			*((unsigned short*)(hello+pool_username.length()+21+pool_password.length())) = 0; //EXTENSIONS
			boost::system::error_code error;
			socket->write_some(boost::asio::buffer(hello, pool_username.length()+2+20+1+pool_password.length()), error);
			//if (error)
			//	std::cout << error << " @ write_some_hello" << std::endl;
			delete[] hello;
		}

		socket_to_server = socket.get(); //TODO: lock/mutex

		int reject_counter = 0;
		bool done = false;
		while (!done) {
			int type = -1;
			{ //get the data header
				unsigned char buf = 0; //get header
				boost::system::error_code error;
				size_t len = boost::asio::read(*socket_to_server, boost::asio::buffer(&buf, 1), boost::asio::transfer_all(), error);
				//size_t len = socket->read_some(boost::asio::buffer(&buf, 1), error);
				if (error == boost::asio::error::eof)
					break; // Connection closed cleanly by peer.
				else if (error) {
					//std::cout << error << " @ read_some1" << std::endl;
					break;
				}
				type = buf;
				if (len != 1)
					std::cout << "error on read1: " << len << " should be " << 1 << std::endl;
			}

			switch (type) {
				case 0: {
					size_t buf_size = 112; //*thread_num_max;
					unsigned char* buf = new unsigned char[buf_size]; //get header
					boost::system::error_code error;
					size_t len = boost::asio::read(*socket_to_server, boost::asio::buffer(buf, buf_size), boost::asio::transfer_all(), error);
					//size_t len = socket->read_some(boost::asio::buffer(buf, buf_size), error);
					//while (len < buf_size)
					//	len += socket->read_some(boost::asio::buffer(buf+len, buf_size-len), error);
					if (error == boost::asio::error::eof) {
						done = true;
						break; // Connection closed cleanly by peer.
					} else if (error) {
						//std::cout << error << " @ read2a" << std::endl;
						done = true;
						break;
					}
					if (len == buf_size) {
						_bprovider->setBlocksFromData(buf);
						std::cout << "[MASTER] work received"<< std::endl;
                        std::cout << "[MASTER] network target:"<< nNetworkBits.ToString().c_str() << std::endl;
                        std::cout << "[MASTER] share target:"<< nShareBits.ToString().c_str() << std::endl;
					} else
						std::cout << "error on read2a: " << len << " should be " << buf_size << std::endl;
					delete[] buf;
					CBlockIndex *pindexOld = pindexBest;
					pindexBest = new CBlockIndex(); //=notify worker (this could need a efficient alternative)
					delete pindexOld;

				} break;
				case 1: {
					size_t buf_size = 4;
					int buf; //get header
					boost::system::error_code error;
					size_t len = boost::asio::read(*socket_to_server, boost::asio::buffer(&buf, buf_size), boost::asio::transfer_all(), error);
					//size_t len = socket->read_some(boost::asio::buffer(&buf, buf_size), error);
					//while (len < buf_size)
					//	len += socket->read_some(boost::asio::buffer(&buf+len, buf_size-len), error);
					if (error == boost::asio::error::eof) {
						done = true;
						break; // Connection closed cleanly by peer.
					} else if (error) {
						//std::cout << error << " @ read2b" << std::endl;
						done = true;
						break;
					}
					if (len == buf_size) {
						int retval = buf > 100000 ? 1 : buf;
						std::cout << "[MASTER] submitted share -> " <<
							(retval == 0 ? "REJECTED" : retval < 0 ? "STALE" : retval ==
							1 ? "BLOCK" : "SHARE") << std::endl;
						std::map<int,unsigned long>::iterator it = statistics.find(retval);
						if (retval > 0)
							reject_counter = 0;
						else
							reject_counter++;
//  					if (reject_counter >= 3) {
//  						std::cout << "too many rejects (3) in a row, forcing reconnect." << std::endl;
//  						socket->close();
//  						done = true;
//  					}
						if (it == statistics.end())
							statistics.insert(std::pair<int,unsigned long>(retval,1));
						else
							statistics[retval]++;
						stats_running();
					} else
						std::cout << "error on read2b: " << len << " should be " << buf_size << std::endl;
				} break;
				case 2: {
					//PING-PONG EVENT, nothing to do
				} break;
				default: {
					//std::cout << "unknown header type = " << type << std::endl;
				}
			}
		}

		socket_to_server = NULL; //TODO: lock/mutex
		for (int i = 0; i < 50 && submitting_share < 1; ++i) //wait <5 seconds until reconnect (force reconnect when share is waiting to be submitted)
			boost::this_thread::sleep(boost::posix_time::milliseconds(100));
	}
  }

  ~CMasterThread() {}

  void wait_for_master() {
    boost::shared_lock<boost::shared_mutex> lock(_mutex_master);
  }

  boost::shared_mutex& get_working_lock() {
    return _mutex_working;
  }

private:

  void wait_for_workers() {
    boost::unique_lock<boost::shared_mutex> lock(_mutex_working);
  }

  CBlockProviderGW  *_bprovider;

  boost::shared_mutex _mutex_master;
  boost::shared_mutex _mutex_working;

	// Provides real time stats
	void stats_running() {
		if (!running) return;
		std::cout << std::fixed;
		std::cout << std::setprecision(1);
		boost::posix_time::ptime t_end = boost::posix_time::second_clock::universal_time();
		unsigned long rejects = 0;
		unsigned long stale = 0;
		unsigned long valid = 0;
		unsigned long blocks = 0;
		for (std::map<int,unsigned long>::iterator it = statistics.begin(); it != statistics.end(); ++it) {
			if (it->first < 0) stale += it->second;
			if (it->first == 0) rejects = it->second;
			if (it->first == 1) blocks = it->second;
			if (it->first > 1) valid += it->second;
		}
		std::cout << "[STATS] " << DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTimeMillis() / 1000).c_str() << " | ";
//  	for (std::map<int,unsigned long>::iterator it = statistics.begin(); it != statistics.end(); ++it)
//  		if (it->first > 1)
//  			std::cout << it->first << "-CH: " << it->second << " (" <<
//  			  ((valid+blocks > 0) ? (static_cast<double>(it->second) / static_cast<double>(valid+blocks)) * 100.0 : 0.0) << "% | " <<
//  			  ((valid+blocks > 0) ? (static_cast<double>(it->second) / (static_cast<double>((t_end - t_start).total_seconds()) / 3600.0)) : 0.0) << "/h), ";
		if (valid+blocks+rejects+stale > 0) {
            char buff[100];
            sprintf(buff, "hashmeter %f hashs/min\n", dHashesPerSec);
            //std::string buffAsStdStr = buff;
        std::cout << buff;
		std::cout << "VL: " << valid+blocks << " (" << (static_cast<double>(valid+blocks) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%), ";
		std::cout << "RJ: " << rejects << " (" << (static_cast<double>(rejects) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%), ";
		std::cout << "ST: " << stale << " (" << (static_cast<double>(stale) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%)" << std::endl;
		} else {
			std::cout <<  "VL: " << 0 << " (" << 0.0 << "%), ";
			std::cout <<  "RJ: " << 0 << " (" << 0.0 << "%), ";
			std::cout <<  "ST: " << 0 << " (" << 0.0 << "%)" << std::endl;
		}
	}
};

/*********************************
* exit / end / shutdown
*********************************/

void stats_on_exit() {
	if (!running) return;
	boost::this_thread::sleep(boost::posix_time::seconds(1));
	std::cout << std::fixed;
	std::cout << std::setprecision(3);
	boost::posix_time::ptime t_end = boost::posix_time::second_clock::universal_time();
	unsigned long rejects = 0;
	unsigned long stale = 0;
	unsigned long valid = 0;
	unsigned long blocks = 0;
	for (std::map<int,unsigned long>::iterator it = statistics.begin(); it != statistics.end(); ++it) {
		if (it->first < 0) stale += it->second;
		if (it->first == 0) rejects = it->second;
		if (it->first == 1) blocks = it->second;
		if (it->first > 1) valid += it->second;
	}
	std::cout << std::endl;
	std::cout << "********************************************" << std::endl;
	std::cout << "*** running time: " << static_cast<double>((t_end - t_start).total_seconds()) / 3600.0 << "h" << std::endl;
	std::cout << "***" << std::endl;
	for (std::map<int,unsigned long>::iterator it = statistics.begin(); it != statistics.end(); ++it)
		if (it->first > 1)
			std::cout << "*** " << it->first << "-chains: " << it->second << "\t(" <<
			  ((valid+blocks > 0) ? (static_cast<double>(it->second) / static_cast<double>(valid+blocks)) * 100.0 : 0.0) << "% | " <<
			  ((valid+blocks > 0) ? (static_cast<double>(it->second) / (static_cast<double>((t_end - t_start).total_seconds()) / 3600.0)) : 0.0) << "/h)" <<
			  std::endl;
	if (valid+blocks+rejects+stale > 0) {
	std::cout << "***" << std::endl;
	std::cout << "*** valid: " << valid+blocks << "\t(" << (static_cast<double>(valid+blocks) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%)" << std::endl;
	std::cout << "*** rejects: " << rejects << "\t(" << (static_cast<double>(rejects) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%)" << std::endl;
	std::cout << "*** stale: " << stale << "\t(" << (static_cast<double>(stale) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%)" << std::endl;
	} else {
		std::cout <<  "*** valid: " << 0 << "\t(" << 0.0 << "%)" << std::endl;
		std::cout <<  "*** rejects: " << 0 << "\t(" << 0.0 << "%)" << std::endl;
		std::cout <<  "*** stale: " << 0 << "\t(" << 0.0 << "%)" << std::endl;
	}
	std::cout << "********************************************" << std::endl;
	boost::this_thread::sleep(boost::posix_time::seconds(3));
}

void exit_handler() {
	//cleanup for not-retarded OS
	if (socket_to_server != NULL) {
		socket_to_server->close();
		socket_to_server = NULL;
	}
	stats_on_exit();
	running = false;
}

#if defined(__MINGW32__) || defined(__MINGW64__)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

BOOL WINAPI ctrl_handler(DWORD dwCtrlType) {
	//'special' cleanup for windows
	switch(dwCtrlType) {
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT: {
			if (socket_to_server != NULL) {
				socket_to_server->close();
				socket_to_server = NULL;
			}
			stats_on_exit();
			running = false;
		} break;
		default: break;
	}
	return FALSE;
}

#elif defined(__GNUG__)

static sighandler_t set_signal_handler (int signum, sighandler_t signalhandler) {
   struct sigaction new_sig, old_sig;
   new_sig.sa_handler = signalhandler;
   sigemptyset (&new_sig.sa_mask);
   new_sig.sa_flags = SA_RESTART;
   if (sigaction (signum, &new_sig, &old_sig) < 0)
      return SIG_ERR;
   return old_sig.sa_handler;
}

void ctrl_handler(int signum) {
	exit(1);
}

#endif //TODO: __APPLE__ ?

/*********************************
* main - this is where it begins
*********************************/
int main(int argc, char **argv)
{
  std::cout << "********************************************" << std::endl;
  std::cout << "*** ptsminer - Pts Pool Miner v" << VERSION_MAJOR << "." << VERSION_MINOR << " " << VERSION_EXT << std::endl;
  //std::cout << "*** by xolokram/TB - www.beeeeer.org - glhf" << std::endl;
  std::cout << "***" << std::endl;
  //std::cout << "*** thx to Sunny King & mikaelh" << std::endl;
  std::cout << "*** press CTRL+C to exit" << std::endl;
  std::cout << "********************************************" << std::endl;

  t_start = boost::posix_time::second_clock::universal_time();
  running = true;

#if defined(__MINGW32__) || defined(__MINGW64__)
  SetConsoleCtrlHandler(ctrl_handler, TRUE);
#elif defined(__GNUG__)
  set_signal_handler(SIGINT, ctrl_handler);
#endif //TODO: __APPLE__

  if (argc < 2)
  {
    std::cerr << "usage: " << argv[0] <<
    " -poolfee=<fee-in-%> -poolip=<ip> -poolport=<port> -pooluser=<user> -poolpassword=<password>" <<
    std::endl;
    return EXIT_FAILURE;
  }

  const int atexit_res = std::atexit(exit_handler);
  if (atexit_res != 0)
    std::cerr << "atexit registration failed, shutdown will be dirty!" << std::endl;

  // init everything:
  ParseParameters(argc, argv);

  socket_to_server = NULL;
  //pool_share_minimum = (unsigned int)GetArg("-poolshare", 7);
  thread_num_max = GetArg("-genproclimit", 1); // what about boost's hardware_concurrency() ?
  fee_to_pay = GetArg("-poolfee", 3);
  miner_id = GetArg("-minerid", 0);
  pool_username = GetArg("-pooluser", "");
  pool_password = GetArg("-poolpassword", "");

  if (thread_num_max == 0 || thread_num_max > MAX_THREADS)
  {
    std::cerr << "usage: " << "current maximum supported number of threads = " << MAX_THREADS << std::endl;
    return EXIT_FAILURE;
  }

  if (fee_to_pay == 0 || fee_to_pay > 100)
  {
    std::cerr << "usage: " << "please use a pool fee between [1 , 100]" << std::endl;
    return EXIT_FAILURE;
  }

  if (miner_id > 65535)
  {
    std::cerr << "usage: " << "please use a miner id between [0 , 65535]" << std::endl;
    return EXIT_FAILURE;
  }

  { //password to sha1
    boost::uuids::detail::sha1 sha;
    sha.process_bytes(pool_password.c_str(), pool_password.size());
    unsigned int digest[5];
    sha.get_digest(digest);
    std::stringstream ss;
    ss << std::setw(5) << std::setfill('0') << std::hex << (digest[0] ^ digest[1] ^ digest[4]) << (digest[2] ^ digest[3] ^ digest[4]);
    pool_password = ss.str();
  }
std::cout << pool_username << std::endl;

  fPrintToConsole = true; // always on
  fDebug          = GetBoolArg("-debug");

  pindexBest = new CBlockIndex();

  //GeneratePrimeTable();

  // ok, start mining:
  CBlockProviderGW* bprovider = new CBlockProviderGW();
  CMasterThread *mt = new CMasterThread(bprovider);
  mt->run();

  // end:
  return EXIT_SUCCESS;
}

//#include "main_poolminer_ex.cpp" //<--TODO

/*********************************
* and this is where it ends
*********************************/
