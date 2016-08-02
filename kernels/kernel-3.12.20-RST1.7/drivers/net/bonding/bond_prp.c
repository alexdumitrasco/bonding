#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/etherdevice.h>
#include <asm/atomic.h>
#include <linux/highmem.h>

#include "./bonding.h"
#include "./bond_prp.h"

typedef enum _tpxPRP_CommonCounters_enum_t
{
	#define		__tpxPRP_CommonCounters_definition_LIST 1
	#define		__tpxPRP_CommonCounters_definition(a) a,
	#include	"bond_prp_counters.h"
	#undef		__tpxPRP_CommonCounters_definition
	#undef		__tpxPRP_CommonCounters_definition_LIST

} tpxPRP_CommonCounters_enum_t;

typedef enum _tpxPRP_PerLanIDCounters_enum_t
{
	#define		__tpxPRP_PerLanIDCounters_definition_LIST 1,
	#define		__tpxPRP_PerLanIDCounters_definition(a) a,
	#include	"bond_prp_counters.h"
	#undef		__tpxPRP_PerLanIDCounters_definition
	#undef		__tpxPRP_PerLanIDCounters_definition_LIST
} tpxPRP_PerLanIDCounters_enum_t;

static struct _tpxPRP_counts_str_t	common_cnts[MaxNumCountersCommon+1] =
{
	#define		__tpxPRP_CommonCounters_definition_LIST 1
	#define		__tpxPRP_CommonCounters_definition(a) {{0}, #a},
	#include	"bond_prp_counters.h"
	#undef		__tpxPRP_CommonCounters_definition
	#undef		__tpxPRP_CommonCounters_definition_LIST
};
static struct _tpxPRP_counts_str_t	perLan_cnts[MaxLanID][MaxNumCountersPerLanID+1] =
{
    {
	#define		__tpxPRP_PerLanIDCounters_definition_LIST 1,
	#define		__tpxPRP_PerLanIDCounters_definition(a) {{0}, #a},
	#include	"bond_prp_counters.h"
	#undef		__tpxPRP_PerLanIDCounters_definition
	#undef		__tpxPRP_PerLanIDCounters_definition_LIST
    },
    {
	#define		__tpxPRP_PerLanIDCounters_definition_LIST 1,
	#define		__tpxPRP_PerLanIDCounters_definition(a) {{0}, #a},
	#include	"bond_prp_counters.h"
	#undef		__tpxPRP_PerLanIDCounters_definition
	#undef		__tpxPRP_PerLanIDCounters_definition_LIST
    },
};

#define	incCnt_Common(cntID)		atomic_inc( &(common_cnts[(cntID)].cnt) )
#define	incCnt_PerLan(cntID,lanID)	atomic_inc( &(perLan_cnts[((lanID) & IF_NDX_MSK)][(cntID)].cnt) )

tpxPRP_str_t			priv[2];
tpxPRP_common_str_t		common;

int bondPRP_init_str(void)
{
    int i=0;

	//printk(KERN_ALERT "%d %s\n",__LINE__,__FUNCTION__);
	memset( &priv,   0, MaxLanID * sizeof(tpxPRP_str_t));
	memset( &common, 0, sizeof(tpxPRP_common_str_t));

	for (i=0; i<(NODE_HASH_MASK+1); i++)
	{
	    common.node[i] = kmalloc(sizeof(tpxPRP_node_str_t), GFP_KERNEL);
	    if (!common.node[i])
	    {
			printk(KERN_ALERT "%d %s: ERROR: kmalloc tpxPRP_node_str_t failed\n",__LINE__,__FUNCTION__);
			return -1;;
	    }
	    memset( common.node[i], 0, sizeof(tpxPRP_node_str_t));
	}
	//printk(KERN_ALERT "%d %s\n",__LINE__,__FUNCTION__);
	return 0;
}

void bondPRP_exit(void)
{
    int i=0;

	//printk(KERN_ALERT "%d %s\n",__LINE__,__FUNCTION__);
	for (i=0; i<(NODE_HASH_MASK+1); i++)
	{
	    memset( common.node[i], 0, sizeof(tpxPRP_node_str_t));
	    kfree( common.node[i]);
	}
}

tpxPRP_str_t *bondPRP_init(u8 if_ndx)
{
    tpxPRP_str_t	*p = NULL;

	if (if_ndx>=2)		return NULL;

	if_ndx &= IF_NDX_MSK;
	p 	= priv  + if_ndx;

	mb();
	p->lanID		= IFNDX2LANID(if_ndx);
	p->netLanID		= LANID2NETLANID(p->lanID);
	p->common		= &common;
	mb();
	//printk(KERN_ALERT"%d %s: ifndx %d, lnID %02x %02x\n",__LINE__,__FUNCTION__,if_ndx,IFNDX2LANID(if_ndx), p->lanID);

	return	p;
}

//inline tpxPRP_str_t *bondPRP_getPRPstrP_by_netdevP( struct net_device *dev)
static tpxPRP_str_t *bondPRP_getPRPstrP_by_netdevP( struct net_device *dev)
{
    //return (tpxPRP_str_t *)(dev->rx_handler_data);
    return ((tpxPRP_str_t *)(rcu_dereference(dev->rx_handler_data)));
}


static inline u32 hash_32(u32 val, int index)
{
	/* On some cpus multiply is faster, on others gcc will do shifts */
	u32 hash = val * GOLDEN_RATIO_PRIME_32;

	/* High bits are more random, so use them. */
	return hash >> (32 - HASH_KEY_LEN - index);
}


//inline static tpxPRP_node_str_t *bondPRP_safeGetNodeByMAC(u8 *mac)
//static tpxPRP_node_str_t *bondPRP_safeGetNodeByMAC(u8 *mac)
tpxPRP_node_str_t *bondPRP_safeGetNodeByMAC(u8 *mac)
{
//    return &common.node;

    int i=0;
    tpxPRP_node_str_t		*pn = NULL;
    volatile u32		 hash = 0;
    //volatile u8			 cmp = 0;
	u64 curTimeStampMS=0,deltaTimeStampMS=0;
    unsigned long flags=0;
	u32 entryID;

    // pentru optimizare as putea sa nu verific
    // deoarece asta a fost facut mai devreme de catre kernel sau MACdevice
    //if( ( !(is_valid_ether_addr(mac)))		return NULL;
    
    // 8bits * 6bytes(MAC) = 48bits(MAC);
    // ca sa fie mai simplu, reducem totul la u32 si avem: 32 - 9(hashMASK) = 23
    #define NumValidBitsInMAC 20
    
    for( pn=NULL, hash=htonl( *((u32 *)(mac+2))), i=0; i<NumValidBitsInMAC; i++)
    //hash=htonl( *((u32 *)(mac+2)));
    //hash &= NODE_HASH_MASK;
    {
		//pn = &(common.node[hash & NODE_HASH_MASK]);
		
		entryID = hash_32(hash, NODE_HASH_Nbits+i);
		pn = common.node[entryID & NODE_HASH_MASK];
	//	printk(KERN_ALERT"%d %s: hash %08x pn %08x used %d\n",__LINE__,__FUNCTION__,hash,(u32)pn,atomic_read(&pn->used));
	//	spin_lock(&pn->lock);
	//	raw_local_irq_save(flags);
		if( atomic_read( &pn->used) )
		{
	//
	//	    printk("MAC: ");
	//	    for(cmp=0,i=0;i<ETH_ALEN;i++)
	//	    {
	//		printk("%02x%02x ",mac[i],pn->mac[i]);
	//		cmp |= (pn->mac[i] ^ mac[i]);
	//	    } printk("\n");
	//	    if(cmp==0)
	//
			//if(  (compare_ether_addr_64bits(const u8 addr1[6+2],const u8 addr2[6+2])) == 0 )
			if(  (compare_ether_addr(mac, pn->mac)) == 0)
				return pn;
			else
			{
				// AICI jiffies ne asigura o precizie suficienta !!!
				curTimeStampMS =jiffies_to_msecs(jiffies);
				spin_lock_irqsave(&pn->lock,flags);
				
				if(curTimeStampMS < pn->lastTimeStampMS)
				{
					deltaTimeStampMS = (curTimeStampMS + (0x0ffffffff - pn->lastTimeStampMS));
				}
				else
				{
					deltaTimeStampMS = (curTimeStampMS - pn->lastTimeStampMS);
				}
				if( deltaTimeStampMS >= 5000) //5 second
				{
					pn->lastTimeStampMS = curTimeStampMS;
					memcpy(pn->mac, mac, ETH_ALEN);
					spin_unlock_irqrestore(&pn->lock,flags);
					return pn;
				}
				spin_unlock_irqrestore(&pn->lock,flags);
			}
		}
		else
		{
	//	    printk(KERN_ALERT"%d %s\n",__LINE__,__FUNCTION__);
			// safeAddMacToNode()
			if( atomic_add_unless(&pn->used,1,1))
			{
	//		printk(KERN_ALERT"%d %s\n",__LINE__,__FUNCTION__);
			memcpy(pn->mac, mac, ETH_ALEN);
	//		spin_unlock(&pn->lock);
	//		raw_local_irq_restore(flags);
			return pn;
			}
			//else(collision) try another empty node
		}
	//	spin_unlock(&pn->lock);
	//	raw_local_irq_restore(flags);
    }
    incCnt_Common(ErrReqToMACtable);
    printk(KERN_ALERT"%d %s: ERROR: exceeded MAC table size %d hash_msk %04x\n",__LINE__,__FUNCTION__,NODE_HASH_MASK+1,NODE_HASH_MASK);
    return NULL;
}

static int bondPRP_add_RCT_prepare(tpxPRP_node_str_t *pn, u8 *pdata, u16 frmSIZE)
{
    tpxPRP_RCT_t	 tmprct;
    u8			*pword = NULL;
    volatile u32	 sendSeqNR=0;

    //  am gasit informatii contradictorii referitor la SequenceNumber,
    //   si anume tre sa am cate un SeqNum per directie(host), sau unul general pentru Tx ????
    //
    //   prin urmare, deocamdata folosesc unul pentru Tx
	sendSeqNR = atomic_add_return(1, &common.sendSeqNR);

	tmprct.seqNR   = htons( sendSeqNR & 0xffff);
	tmprct.frmSIZE = htons(frmSIZE);

	pword = (u8 *)(& tmprct);

	pdata[0] = pword[0];
	pdata[1] = pword[1];
	pdata[2] = pword[2];
	pdata[3] = pword[3];
	pdata[4] = PRP_ETHTYPEprp_L;
	pdata[5] = PRP_ETHTYPEprp_H;
	return 0;
}

struct sk_buff *bondPRP_tx_prepare(struct sk_buff *skb)
{
	tpxPRP_node_str_t *pn = NULL;
	struct sk_buff  *skb2 = NULL;
	u16 size = 0;
	int length = 0, i;
	int padlen = 0;
	int ethFrmSize = skb->len;
	int ret;
	u8	*dstmac	 = 0;
	u8	*pdata	 = 0;
	u32	tailroom = 0;

	incCnt_Common(TxFrm);
	if( skb_is_nonlinear(skb))
	{
		incCnt_Common(TxErrFrmIsNonLinear);
		// !!! TREBUIE un CONTOR si pentr-u FRAMEurile astea !!!
		// ies fara sa modific ceva, las pe KERNEL sa decida ce sa faca cu el.
		//printk(KERN_ALERT"%d %s: ERROR: skb_is_nonlinear(): we can't handle nonlinear buffers\n",__LINE__,__FUNCTION__);


		// aici trebuie sa folosesc skb_copy_expand verific daca lungime packet mai mare ca valori de mai jos 
		// MIN_MTU in loc de 64
		//if (skb->data_len < ETHER_TYPE_SIZE+PRP_ETHTYPEvlanHDR_SIZE)
		skb2 = skb_copy_expand(skb, START_OFFSET, MIN_FRAME_SIZE, GFP_ATOMIC);
		dev_kfree_skb(skb);
    	skb = skb2;
    	if (!skb)
    	{
			incCnt_Common(TxErrSkbCpyExpand);
			printk(KERN_ALERT "%d %s: ERROR: skb_copy_expand()\n",__LINE__,__FUNCTION__);
			goto out;
  		}
	}

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	/* If packet is not checksummed and device does not
	 * support checksumming for this protocol, complete
	 * checksumming here.
	 */
	//features = netif_skb_features(skb);
	if (skb->ip_summed == CHECKSUM_PARTIAL)
	{
		if (skb->encapsulation)
		{
			skb_set_inner_transport_header(skb, skb_checksum_start_offset(skb));
		}
		else
		{
			skb_set_transport_header(skb, skb_checksum_start_offset(skb));
		}
		//if (!(features & NETIF_F_ALL_CSUM) &&
		if ( skb_checksum_help(skb))
		{
			//goto out_kfree_skb; //problema ???
			goto out;
		}
	}
	#endif
	
	// pentru a exclude situatia in care RCT-ul e pus inainte
	// de a avea un paket minim de 64 bytes
	// adaugam noi date pina se indeplineste conditia minima de marime a pketului
	//
	// !!! atentie VLAN !!! in cazul in care tag-ul vlan este exclus,
	//	(de exemplu un nod intermediar) marimea paketului nu va mai fi minima,
	//	si se vor adauga octeti astfel incat RCT-ul nu va mai fi in coada packetului
	//	pentru a exclude aceasta situatie, marimea packetului in cazul VLAN tre sa fie de 68
	//
	// adica :
	//	srcMAC		6  bytes
	//	dstMAC		6  bytes
	//	ETHtype		2  bytes
	//	802.1Q(VLAN)	4  bytes
	//	DATA	minim	46 bytes(daca VLAN atunci 42 insa noi tot 46 punem, vezi mai sus)
	//	CRC		4  bytes
	//
	// prin urmare:
	//
	// pentru nonVLAN:
	// padlen = MIN-MTU_SIZE - minDATA  - PRP_RCT - CRC ==> 64 - 46 - 4 - 4 = 12
	// pentru VLAN:
	// padlen = MIN-MTU_SIZE - minDATA  - PRP_RCT - CRC ==> 64 - 46 - 4 - 4 = 12
	//
	// !!!!!! atentie tre verificate cifrele astea MAGICE si puse frumos sub DEFINE !!!!!!
	//

	// Initializam size cu o valoare default pt caz general nonVLAN
	// calculate LSDU_size for non VLAN-Tagged frame
	
	// MIN_MTU(64) - ( MAC_DST(6) + MAC_SRC(6) + ETHER_TYPE(2) + CRC(4) + PRP_RCT(6) ) = 40
	/*size = length - (ETH_HLEN + CRC_SIZE);	

	for( i=ETH_2_ALEN; i < ethFrmSize; i+=PRP_ETHTYPEvlanHDR_SIZE)
	{
		printk("%s %d\n", __FUNCTION__, __LINE__);
		if ((pdata[ETH_2_ALEN] == PRP_ETHTYPEvlan_L) && (pdata[ETH_2_ALEN+1] == PRP_ETHTYPEvlan_H))
			// calculate LSDU_size for VLAN-Tagged frame
			size -= PRP_ETHTYPEvlanHDR_SIZE;
		else			
			break;
	}*/

	// !!!!!! atentie tre verificate cifrele astea MAGICE si puse frumos sub DEFINE !!!!!!
	
	if (skb->len < (MIN_DATA - PRP_RCT_SIZE))
		padlen = MIN_DATA - PRP_RCT_SIZE - skb->len;
	else
		padlen = 0;

	tailroom = skb_tailroom(skb);
	if (tailroom < (padlen + PRP_RCT_SIZE))
	{
	    skb2 = skb_copy_expand(skb, 0, (PRP_RCT_SIZE + padlen + 10), GFP_ATOMIC);
	    dev_kfree_skb(skb);
	    skb = skb2;
	    if (!skb)
	    {
			incCnt_Common(TxErrSkbCpyExpand);
			printk(KERN_ALERT "%d %s: ERROR: skb_copy_expand()\n",__LINE__,__FUNCTION__);
			goto out;
	    }
	}
	
	// pad such that length would be >=60 bytes
	//	(without CRC, without VLAN tag, without PRP trailer)
	
	for (pdata=skb->data, length = (skb->tail-skb->data-CRC_SIZE), i=0; i < padlen; i++,length++)
	{
		pdata[length] = 0;
	}

	/* Used data area extended with padlen */
	pdata = skb_put(skb, padlen+PRP_RCT_SIZE);
	if( !(pdata))
	{
		incCnt_Common(TxErrSkbPutPadLngh);
		printk(KERN_ALERT "%d %s: ERROR: skb_put()\n",__LINE__,__FUNCTION__);
		dev_kfree_skb(skb);
		skb=NULL;
		goto out;
	}

	dstmac = skb->data;
	pn = bondPRP_safeGetNodeByMAC(dstmac);

	if( !pn)
	{
	    printk(KERN_ALERT "%d %s: ERROR: bondPRP_safeGetNodeByMAC()\n",__LINE__,__FUNCTION__);
	    dev_kfree_skb(skb);
	    skb=NULL;
	    goto out;
	}

	bondPRP_add_RCT_prepare(pn, pdata, (skb->len - 14));
	incCnt_Common(TxFrmOK);

out:
	return skb;
}

struct sk_buff *bondPRP_tx_adLanID(struct sk_buff *skb, struct net_device *tx_dev)
{
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,20)
	struct slave    *slave=NULL;
    #endif
	tpxPRP_str_t	*prp=NULL;

	u8	*pdata	 =0;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,20)
	slave = bond_slave_get_rcu(tx_dev);
	prp = (tpxPRP_str_t *)(slave->prp);
    #else
	//prp=bondPRP_getPRPstrP_by_netdevP(tx_dev);
	prp=(tpxPRP_str_t *)(tx_dev->rx_handler_data);
    #endif

	if( !prp || !skb )
	{
	    printk(KERN_ALERT"%d %s: ERROR: prp %08x txdev %08x\n\n",__LINE__,__FUNCTION__,(u32)prp,(u32)skb);
	    return NULL;
	}

	pdata = skb_tail_pointer(skb);
	pdata -= PRP_RCT_SIZE;
	mb();
//	bondPRP_add_lanID2RCT(prp,NULL,pdata);
	pdata[2] &= 0x0f;
	pdata[2] |= (prp->netLanID & PRP_RCT_LAN_ID_MSK);
	mb();

	return skb;
}

struct sk_buff *bondPRP_rx_frameTYPE_supervision(struct sk_buff *skb, u16 ethFrmSIZE, u16 ethHdrSIZE)
{
    incCnt_Common(RxFrmSupervision);
    //printk(KERN_ALERT "frame supervision\n");

    kfree_skb(skb);
    skb=NULL;
    return NULL;
}

struct sk_buff *bondPRP_rx_frameTYPE_regular(struct sk_buff *skb, u16 ethFrmSIZE, u16 ethHdrSIZE)
{
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,20)
	struct slave    *slave=NULL;
    #endif

    tpxPRP_str_t	*prp=NULL;
    tpxPRP_node_str_t	*pn=NULL;

    u8 *pdata=NULL;
    u8 *machdr=NULL;
    u8 *macptr=NULL;
    u8 dstmac[ETH_ALEN];	
	u8 prp_tail[PRP_RCT_SIZE];

	int i=0, ret;

    volatile u8  lanID=0;
    volatile u16 rcvSeqNR=0;
    volatile u16 prpFrmSIZE=0;
    volatile u16 lsduFrmSIZE=0;
    #if defined(CONFIG_ARCH_M828XX) || defined(CONFIG_ARCH_M83XXX)
    // pentru Comcerto, deoarece el lasa coada PRP-ului insa raporteza ca a taeato
    volatile u16 tailroom=0;
    volatile u16 prp_rct_trimed_size=0;
    volatile u16 prp_rct_size_to_trim=0;
    #endif
    volatile u64 currTimeStampMS=0;
    volatile u64 lastTimeStampMS=0;
    volatile u64 deltaTimeStampMS=0;
		
    struct timeval tv;
	ktime_t ktime_now;
	ktime_t ktime_prev;
	ktime_t ktime_delta;

    //unsigned long flags=0;

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,20)
	slave = bond_slave_get_rcu(skb->dev);
	prp = (tpxPRP_str_t *)(slave->prp);
    #else
	//prp=bondPRP_getPRPstrP_by_netdevP(tx_dev);
	prp=(tpxPRP_str_t *)(tx_dev->rx_handler_data);
    #endif

	//printk(KERN_ALERT "Frame type regular %d %d\n",ethFrmSIZE,ethHdrSIZE);
    if(unlikely(!prp))
    {
		printk(KERN_ALERT"%d %s: ERROR: null pointer for prp\n",__LINE__,__FUNCTION__);
		goto out_ok;
    }
	
	incCnt_PerLan(RxFrmOnLan, prp->lanID);

	#if defined(CONFIG_ARCH_M828XX) || defined(CONFIG_ARCH_M83XXX)
	// verificare in plus pentru Comcerto,
	// deoarece el lasa coada PRP-ului insa raporteza ca a taiat-o
	tailroom = skb_tailroom(skb);
	if( tailroom < PRP_RCT_SIZE)
	{
		incCnt_PerLan(RxPRPtrailerNotTrimedSkbOnLan, prp->lanID);
		prp_rct_trimed_size=0;
		prp_rct_size_to_trim=PRP_RCT_SIZE;
		printk(KERN_ALERT"WARNING: skb_tailroom() < PRP_RCT_SIZE\n");
		//goto out_ok;
	}
	else
	{
		incCnt_PerLan(RxPRPtrailerTrimedSkbOnLan, prp->lanID);
		prp_rct_trimed_size=PRP_RCT_SIZE;
		prp_rct_size_to_trim=0;
	}

	pdata = skb_tail_pointer(skb);
	pdata -= prp_rct_size_to_trim;
	#else
	pdata = skb_tail_pointer(skb);
	//pdata -= PRP_RCT_SIZE;
	
	ret = skb_copy_bits(skb, skb->len-PRP_RCT_SIZE, prp_tail, PRP_RCT_SIZE);

	if (ret != 0)
	{
		printk("Error skb_copy_bits prp tail ret=%d\n", ret);
		goto out_drop;
	}

	pdata = prp_tail;
	#endif

	macptr = skb_mac_header(skb) + ETH_ALEN;
	pn = bondPRP_safeGetNodeByMAC(macptr);
	if( !pn)
	{
//		printk(KERN_ALERT"%d %s: ERROR: bondPRP_safeGetNodeByMAC(mac) %08x\n",__LINE__,__FUNCTION__,(u32)pn);
		goto out_ok;
	}
	#if defined(CONFIG_ARCH_M828XX) || defined(CONFIG_ARCH_M83XXX)
	// verificare in plus pentru Comcerto,
	// deoarece el lasa coada PRP-ului insa raporteza ca a taiato
	if( (pdata[4] != 0x088) || (pdata[5] != 0x0FB))
	{
		if(prp_rct_size_to_trim == 0)
		{
                    prp_rct_trimed_size=0;
                    pdata -= PRP_RCT_SIZE;
	#endif
		    if( (pdata[4] != 0x088) || (pdata[5] != 0x0FB))
		    {
				incCnt_PerLan(RxErrNoPRPtrailerOnLan, prp->lanID);
//                        printk(KERN_ALERT"ERROR: wrong PRPtrailerTYPE %02x%02x\n",pdata[4],pdata[5]);
				goto out_ok;
			}
//                    else
//                    {
//                        printk(KERN_ALERT"found correct PRPtrailerTYPE %02x%02x, PRP_RCT not trimed\n",pdata[4],pdata[5]);
//                    }
#if defined(CONFIG_ARCH_M828XX) || defined(CONFIG_ARCH_M83XXX)
		}
		else
		{
			incCnt_PerLan(RxErrNoPRPtrailerOnTrimedSkbOnLan, prp->lanID);
//                        printk(KERN_ALERT"ERROR: wrong PRPtrailerTYPE %02x%02x\n",pdata[4],pdata[5]);
			goto out_ok;
		}
	}
	#endif

	lanID       = NET_LAN_ID_MSK & pdata[2];
	rcvSeqNR    = ntohs( *((u16 *)((u8 *)pdata +0)) );
	prpFrmSIZE  = ntohs( *((u16 *)((u8 *)pdata +2)) );
	prpFrmSIZE &= 0x0fff;

	if ((lanID != PRP_RCT_LAN_ID_A) && (lanID != PRP_RCT_LAN_ID_B))
	{
		//atomic_inc_return(&pstats->cntErrUnknownLanID);
		incCnt_PerLan(RxErrUnknownLanIDOnLan, prp->lanID);
		printk(KERN_ALERT"%d %s: ERROR: unknown lanID %02x\n",__LINE__,__FUNCTION__,lanID);
		goto out_ok;
	}
	if (lanID != prp->netLanID)
	{
		//atomic_inc_return(&pstats->cntErrWrongLanID);
		incCnt_PerLan(RxErrWrongLanIDOnLan, prp->lanID);
		printk(KERN_ALERT"%d %s: seqNR %04x ERROR: wrong lanID %02x received on lan %02x: prp %08x, %08x %08x, %s\n",__LINE__,__FUNCTION__,rcvSeqNR,lanID,prp->netLanID,(u32)prp,(u32)priv,(u32)(priv+1),skb->dev->name);
		goto out_ok;
	}
	#if defined(CONFIG_ARCH_M828XX) || defined(CONFIG_ARCH_M83XXX)
	// pentru ca firmware-ul MSP trunchiaza PRP_RCT-ul
	lsduFrmSIZE = ethFrmSIZE - ethHdrSIZE +prp_rct_trimed_size;
	#else
	lsduFrmSIZE = ethFrmSIZE - ethHdrSIZE;
	#endif
	if (prpFrmSIZE != lsduFrmSIZE)
	{
		//atomic_inc_return(&pstats->cntErrWrongFrmSize);
		incCnt_PerLan(RxErrWrongFrmSizeOnLan, prp->lanID);
		printk(KERN_ALERT"%d %s: ERROR: wrong prpFrmSIZE %d lsduFrmSIZE %d; ethFrmSize %d ethHdrSize %d, %s\n",__LINE__,__FUNCTION__,prpFrmSIZE,lsduFrmSIZE,ethFrmSIZE,ethHdrSIZE,skb->dev->name);
		goto out_ok;
	}
	incCnt_PerLan(RxFrmOkOnLan, prp->lanID);

	ktime_now = ktime_get();
	currTimeStampMS = ktime_to_ms(ktime_now);

	spin_lock(&pn->lock);
	lastTimeStampMS = pn->lastTimeStampForSeqNR[rcvSeqNR & PRP_DROP_WINDOW_MSK];
	pn->lastTimeStampForSeqNR[rcvSeqNR & PRP_DROP_WINDOW_MSK] = currTimeStampMS;
	spin_unlock(&pn->lock);

	ktime_prev = ms_to_ktime(lastTimeStampMS);	

	ktime_delta = ktime_sub(ktime_now, ktime_prev);
	deltaTimeStampMS = ktime_to_ms(ktime_delta);
	
	if( deltaTimeStampMS < PRP_DROP_WINDOW_DeltaMiliSec)
	{
		incCnt_PerLan(RxFrmDrOnLan, prp->lanID);
		goto out_drop;
	}

	// !!!!!!!!! pentru OPTIMIZARE si EVITARE ERORI, NUUUU truncam paketul !!!!!!
	// aici tre sa dau jos PRP-RCT-ul
	// teoretic e optional, IP-ul are lungimea lui si respectiv ar trebui sa ignore restul.
        // in unele cazuri nu e nevoie sa trunchiez, o face MSP-ul
        //#if defined(CONFIG_ARCH_M828XX) || defined(CONFIG_ARCH_M83XXX)
        //if(prp_rct_size_to_trim)
        //#endif
        //{
        //    pskb_trim_rcsum(skb, (skb->len - PRP_RCT_SIZE));
        //}
	incCnt_Common(RxFrmOK);
 	out_ok:
		return skb;
    out_drop:
		kfree_skb(skb);
		skb=NULL;
		return NULL;
}

struct sk_buff *bondPRP_rx(struct sk_buff *skb)
{
    int i=0, offset=0, ret;
    u8 *pdata=NULL;
    u16 ethHdrSize=0;
    u16 ethFrmSize=0;
    struct sk_buff *skb_tmp;
	int j;

	incCnt_Common(RxFrm);

	// deoarece la transmitere, in cazul PRP, obligatoriu se asigura MIN-MTU=64
	// aici verific lungimea frame-ului sa fie >= 60
	// 64(minMTU) - 4(CRC) = 60
	//
	// lungimea skb->len e scurtata anterior de kernel cu functia eth_type_trans()
	// adica au scazut header-ul MAC
	// prin urmare: 64(minMTU) - 14(dstMAC(6) + srcMAC()6 + ETHtype(2)) - 4(CRC)= 46
	if(skb->len < MIN_DATA)
	{
		incCnt_Common(RxErrFrmTooShort);
		// !!! TREBUIE un CONTOR si pentr-u FRAMEurile astea !!!
		// ies fara sa modific ceva, las pe KERNEL sa decida ce sa faca cu el.
		printk(KERN_ALERT"%d %s: ERROR: skb->len(%d) < 46\n",__LINE__,__FUNCTION__,skb->len);
		return skb;
	}

	if( skb_shinfo(skb)->nr_frags) 
	{
		incCnt_Common(RxErrFrmIsNonLinear);
		// !!! TREBUIE un CONTOR si pentr-u FRAMEurile astea !!!
		// ies fara sa modific ceva, las pe KERNEL sa decida ce sa faca cu el.	
	}
	else 
		pdata = skb_mac_header(skb);

	// aici incepe magia VlanQinQ (802.1ad)
	ethHdrSize   = ETH_HLEN;
	ethFrmSize   = skb->len + ETH_HLEN;

	for( ethHdrSize = ETH_HLEN, i=ETH_2_ALEN; i < ethFrmSize; i+=PRP_ETHTYPEvlanHDR_SIZE, 
																	ethHdrSize+=PRP_ETHTYPEvlanHDR_SIZE)
	{
		pdata = skb_mac_header(skb);
		offset = i;
	
		if (skb->len < offset + 1) {
			printk(KERN_ALERT "%s %d skb_len %d offs %d\n", __FUNCTION__, __LINE__, skb->len, offset+1);
			return skb;
		}

		if ((pdata[offset] == PRP_ETHTYPEvlan_L) && (pdata[offset+1] == PRP_ETHTYPEvlan_H))
		{
			continue;
		}
		else if ((pdata[offset] == PRP_ETHTYPEprp_L) && (pdata[offset+1] == PRP_ETHTYPEprp_H))
		{
			return bondPRP_rx_frameTYPE_supervision(skb, ethFrmSize, ethHdrSize);
		}
		else {
			return bondPRP_rx_frameTYPE_regular(skb, ethFrmSize, ethHdrSize);
		}
	}

	err_unknown:
	incCnt_Common(RxErrUnknown);
	// daca am ajuns aici e nasol, inseamna ca am ajuns la capatul FRAME-ului
	//   dar nam gasit nici un header cu ETHERtype cunoscut.
	// printez ceva ERROR ?????
    return skb;
}


ssize_t bondPRP_sysfs_show_prp_stats(struct bonding *bond, char *buf)
{
        int count = 0, i=0, cntMACNodes=0, cntMACNodesExpired=0;
        u32 curTimeStampMS=0,lastTimeStampMS=0,deltaTimeStampMS=0;

		count += sprintf(buf+count, "\n");
        if (bond->params.mode == BOND_MODE_PRP)
        {
            count += sprintf(buf+count, "%32s %32s\n","CountersName","CountersValue");
            count += sprintf(buf+count, "\n");
            for(i=0; i<MaxNumCountersCommon; i++)
            {
                count += sprintf(buf+count, "%32s %32d\n",  common_cnts[i].name,
                                            atomic_read( &common_cnts[i].cnt) ) + 1;
            }
            count += sprintf(buf+count, "\n");
            count += sprintf(buf+count, "%32s %32s %32s\n","CountersName","CountersValueForLan_A","CountersValueForLan_B");
            count += sprintf(buf+count, "\n");
            for(i=0; i<MaxNumCountersPerLanID; i++)
            {
                count += sprintf(buf+count, "%32s %32d %32d\n", perLan_cnts[0][i].name,
                                                atomic_read( &perLan_cnts[0][i].cnt),
                                                atomic_read( &perLan_cnts[1][i].cnt) ) + 1;
            }
			count += sprintf(buf+count, "\n");
			count += sprintf(buf+count, "%32s %32s\n","CountersName","CountersValue");
			count += sprintf(buf+count, "\n");
			for(cntMACNodes=0,i=0; i<(NODE_HASH_MASK+1); i++)
			{
				if(atomic_read(&(common.node[i]->used)))
				{
					curTimeStampMS	= jiffies_to_msecs(jiffies);
					lastTimeStampMS	= common.node[i]->lastTimeStampMS;
					if(curTimeStampMS < lastTimeStampMS)
					{
						deltaTimeStampMS = (curTimeStampMS + (0x0ffffffff - lastTimeStampMS));
					}
					else
					{
						deltaTimeStampMS = (curTimeStampMS - lastTimeStampMS);
					}
					if( deltaTimeStampMS >= 1000) //1 second
					{
						cntMACNodes++;
					}
					else
					{
						cntMACNodesExpired++;
					}
				}
			}

			count += sprintf(buf+count, "%32s %32d\n","cntMACNodes",cntMACNodes) + 1;
			count += sprintf(buf+count, "%32s %32d\n","cntMACNodesExpired",cntMACNodesExpired) + 1;
        }
        else
        {
			count += sprintf(buf+count, "bonding is not configured as PRP mode\n");
        }
        count += sprintf(buf+count, "\n");
	//add extra character for NULL terminated string
        count++;
		buf[count]=0x0;

        return count;
}
