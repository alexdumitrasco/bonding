//====================================================================================================

//====================================================================================================
#ifndef __BOND_PRP_H__
#define __BOND_PRP_H__
//====================================================================================================

#define ETH_2_ALEN		((2)*ETH_ALEN)
#define MIN_FRAME_SIZE	64
#define MIN_DATA		46			/* 64(MIN_FRAME_SIZE)- 14(HEADER_SIZE) - 4(CRC_SIZE)= 46 */
#define HEADER_SIZE		14
#define CRC_SIZE		4
#define START_OFFSET	0

//====================================================================================================
#define PRP_ETHTYPEprpHDR_SIZE		2
#define PRP_ETHTYPEprp_L		0x088
#define PRP_ETHTYPEprp_H		0x0FB
//====================================================================================================
#define PRP_ETHTYPEvlanHDR_SIZE		4
#define PRP_ETHTYPEvlan_L		0x081
#define PRP_ETHTYPEvlan_H		0x000
//====================================================================================================
//#define PRP_RCT_SIZE		4	// in bytes
#define PRP_RCT_SIZE		6	// RCT + ETHTYPEprp
//====================================================================================================
#define PRP_RCT_LAN_ID_MSK	0x0f0
#define PRP_RCT_LAN_ID_A	0x0a0
#define PRP_RCT_LAN_ID_B	0x0b0
//====================================================================================================
#define IF_NDX_MSK		0x001
#define MaxLanID		(IF_NDX_MSK +1)
#define START_LAN_ID		0x00a
#define NET_LAN_ID_MSK		0x0f0
//====================================================================================================
#define LANID2IFNDX(lanID)	 ((lanID)  & IF_NDX_MSK)
#define IFNDX2LANID(if_ndx)	(((if_ndx) & IF_NDX_MSK) | START_LAN_ID)
#define LANID2NETLANID(lanID)	(((lanID) << 4) & NET_LAN_ID_MSK)
//====================================================================================================

//====================================================================================================
//====================================================================================================

//====================================================================================================
typedef struct _tpxPRP_RCT_t
{
    volatile u16		seqNR;		// 16-bit sequence Number
    volatile u16		frmSIZE;	// 4-bit LANidentifier | 12-bit frame size

} tpxPRP_RCT_t;
/*
typedef struct _tpxPRP_stats_str_t
{
    atomic_t			sendSeqNR;		// 16-bit sequence Number; localNODE to remoteNODE
    atomic_t			expectedSeqNr;		// 16-bit sequence Number; expected from remoteNODE
    atomic_t			startSeqNr;		// 16-bit sequence Number; start to DROP frames from this.
    
    atomic_t			cntRcvdFrms;		// number of frames received
    
    atomic_t			cntErrNoPRPtrailer;
    atomic_t			cntErrUnknownLanID;
    atomic_t			cntErrWrongLanID;
    atomic_t			cntErrWrongFrmSize;
    
    atomic_t			cntErrOutOfSeq;		// number of frames received with out of sequence
    
} tpxPRP_stats_str_t;
*/
typedef struct _tpxPRP_counts_str_t
{
    atomic_t	 cnt;
    u8		*name;

} tpxPRP_counts_str_t;

typedef struct _tpxPRP_node_str_t
{
    atomic_t			used;
    //
    // din cauza lipsei documentului IEC62439-3,
    //  am gasit informatii contradictorii referitor la SequenceNumber,
    //   si anume tre sa am cate un SeqNum per directie(host), sau unul general pentru Tx ????
    //
    //   daca folosesc per directie(HOST) le diferentiez dupa MAC destinatie,
    //     ce ma fac daca trimit MULTICAST sau BRODCAST???
    //
    // prin urmare, deocamdata folosesc unul pentru Tx
    //
    //tpxPRP_stats_str_t	stats[IF_NDX_MSK+1];
    //atomic_t			sendSeqNR;		// 16-bit sequence Number; localNODE to remoteNODE

    u8				mac[ETH_ALEN];

    //	Aging time callcullation:
    //		Count(seq_nr; PRP_DROP_WINDOW_MSK) / MaxFramesPer_ms(100Mbps/1500Bytes/8bits/1000)
    //
    //		PRP_DROP_WINDOW_MSK 0x0ffff	=	2^16 / ~200 = ~330 ms
    //		PRP_DROP_WINDOW_MSK 0x07fff	=	2^14 / ~200 =  ~80 ms
    //		PRP_DROP_WINDOW_MSK 0x01fff	=	2^13 / ~200 =  ~40 ms
    //		PRP_DROP_WINDOW_MSK 0x00fff	=	2^12 / ~200 =  ~20 ms
    //		PRP_DROP_WINDOW_MSK 0x007ff	=	2^10 / ~200 =   ~5 ms
    //		PRP_DROP_WINDOW_MSK 0x000ff	=	2^8  / ~200 =   ~1 ms

    #define PRP_DROP_WINDOW_MSK			0x0fff
    #define PRP_DROP_WINDOW_DeltaMiliSec	100

    u64				lastTimeStampForSeqNR[PRP_DROP_WINDOW_MSK+1]; //in miliseconds

    u64				lastTimeStampMS; //in miliseconds
    spinlock_t			lock;

} tpxPRP_node_str_t;

typedef struct _tpxPRP_nodesTable_str_t
{
    //
    // din cauza lipsei documentului IEC62439,
    //  am gasit informatii contradictorii referitor la SequenceNumber,
    //   si anume tre sa am cate un SeqNum per directir(host), sau unul general pentru Tx ????
    //
    //   daca folosesc per directie(HOST), atunci le diferentiez dupa MAC destinatie,
    //     ce ma fac daca trimit MULTICAST sau BRODCAST???
    //
    // prin urmare, deocamdata folosesc unul pentru Tx
    //
    atomic_t			sendSeqNR;	// 16-bit sequence Number; localNODE to remoteNODE
    atomic_t			lastSeqNR;	// 16-bit sequence Number; localNODE to remoteNODE

    // deocamdata o sa folosesc o idee GENIALA :) :) :) de lookup table
    // mai tarziu tre sa folosesc acelas mecanizm ca la "neighbour table manipulation"
    // adica vestitul RCU-list
    // !!!! tre sa studiez "neighbour table manipulation" !!!!
    //
    //  -- ideea GENIALA consta in:--
    // folosesc 9 biti din MAC pentru keiea de lookup in tabel
    // daca dau de o coliziune, deplasez cu un bit si folosesc urmatorii 9 biti
    // prin acest mecanizm o sa am acces rapid, si rezolv problema coliziunilor.
    // accesul concurent se rezolva prin spin_lock
    //
    // DEZAVANTAJE:
    // odata cu cresterea numarului de hosturi, creste numarul coliziunilor,
    // va creste si timpul de cautare.
    // solutie rapida: se trece la 10 biti, sau mai multi(creste mul tabelul, ocupam mult RAM)

    #define GOLDEN_RATIO_PRIME_32	0x9e370001UL

    // 8bits * 6bytes(MAC) = 48bits(MAC);
    // ca sa fie mai simplu, reducem totul la u32 si avem: 32 - 10(hashMASK) = 22
    #define NumValidBitsInMAC 22

    #define	NODE_HASH_MASK		0x03ff
    #define	NODE_HASH_Nbits		10
    
    tpxPRP_node_str_t		*node[NODE_HASH_MASK+1];

}tpxPRP_common_str_t;

typedef struct _tpxPRP_str_t
{
    volatile u8			lanID;		// 0x0a respectiv 0x0b
    volatile u8			netLanID;	// (lanID << 4) 0x0a0 respectiv 0x0b0 in loca de 0x0a respectiv 0x0b

    tpxPRP_common_str_t		*common;

} tpxPRP_str_t;
//====================================================================================================

//====================================================================================================
int  bondPRP_init_str(void);
void bondPRP_exit(void);
//====================================================================================================
tpxPRP_str_t	*bondPRP_init(u8 if_ndx);
//====================================================================================================

//====================================================================================================
struct sk_buff	*bondPRP_tx_prepare(struct sk_buff *skb);
struct sk_buff	*bondPRP_tx_adLanID(struct sk_buff *skb, struct net_device *tx_dev);
//====================================================================================================

//====================================================================================================
struct sk_buff	*bondPRP_rx(struct sk_buff *skb);
//====================================================================================================
ssize_t bondPRP_sysfs_show_prp_stats(struct bonding *bond, char *buf);
//====================================================================================================
//	compatibilitatea cu versiuni mai vechi de kernel
//====================================================================================================
#include <linux/version.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,21)
static inline unsigned char *skb_tail_pointer(const struct sk_buff *skb)
{
	return (unsigned char *)(skb->tail);
}
static inline unsigned char *skb_mac_header(const struct sk_buff *skb)
{
	return (unsigned char *)(skb->mac.raw);
}
#endif
//====================================================================================================
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,11)
/**
 * compare_ether_addr - Compare two Ethernet addresses
 * @addr1: Pointer to a six-byte array containing the Ethernet address
 * @addr2: Pointer other six-byte array containing the Ethernet address
 *
 * Compare two ethernet addresses, returns 0 if equal
 */
static inline unsigned compare_ether_addr(const u8 *addr1, const u8 *addr2)
{
        const u16 *a = (const u16 *) addr1;
        const u16 *b = (const u16 *) addr2;

        BUILD_BUG_ON(ETH_ALEN != 6);
        return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0;
}
/**
 *      pskb_trim_rcsum - trim received skb and update checksum
 *      @skb: buffer to trim
 *      @len: new length
 *
 *      This is exactly the same as pskb_trim except that it ensures the
 *      checksum of received packets are still valid after the operation.
 */
/*
#include <linux/skbuff.h>
static inline int pskb_trim_rcsum(struct sk_buff *skb, unsigned int len)
{
        if (likely(len >= skb->len))
                return 0;
        if (skb->ip_summed == CHECKSUM_COMPLETE)
                skb->ip_summed = CHECKSUM_NONE;
        return __pskb_trim(skb, len);
}
*/
static inline void pskb_trim_rcsum(struct sk_buff *skb, unsigned int len)
{
    (void)skb_trim(skb,len);
}
#endif
//====================================================================================================
#endif // __BOND_PRP_H__
//====================================================================================================

//====================================================================================================
