/*
 * G6-Chain 分布式协作开发框架 (Team Version)
 * ==========================================================
 * 【项目说明】
 * 本项目是一个基于C语言的区块链模拟系统。
 * 项目已预置：系统架构、加密库、文件存储、UI交互。
 * 组员需完成：核心数据结构与算法逻辑 (见下方 MODULE A - E)。
 *
 * 【开发指南】
 * 1. 搜索 "MODULE X" (X是你选择的模块，如 MODULE A)。
 * 2. 阅读注释中的 "任务目标" 和 "实现提示"。
 * 3. 删除临时的 return 语句，编写你的逻辑。
 * 4. 尽可能尝试 "加分拓展项"。
 * ==========================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#endif

// === 1. 基础配置 (不可修改) ===
#define CHAIN_FILE   "blockchain.dat"
#define MINER_FILE   "miners.dat"
#define CONTACT_FILE "contacts.dat"
#define MEMPOOL_FILE "mempool.dat"
#define MAX_TX_PER_BLOCK 10
#define MEMPOOL_SIZE 100
#define BLOCK_INTERVAL 10 

// === 2. SHA-256 加密库 (直接调用) ===
// 功能：calc_sha256(input, output) -> 将字符串 input 加密为 64位哈希 output
#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define SIG0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define SIG1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define EP1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
static const uint32_t K[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
void sha256_transform(uint32_t*s,const uint8_t*d){uint32_t a,b,c,d2,e,f,g,h,t1,t2,m[64],i;for(i=0;i<16;++i)m[i]=(d[i*4]<<24)|(d[i*4+1]<<16)|(d[i*4+2]<<8)|d[i*4+3];for(;i<64;++i)m[i]=SIG1(m[i-2])+m[i-7]+SIG0(m[i-15])+m[i-16];a=s[0];b=s[1];c=s[2];d2=s[3];e=s[4];f=s[5];g=s[6];h=s[7];for(i=0;i<64;++i){t1=h+EP1(e)+CH(e,f,g)+K[i]+m[i];t2=EP0(a)+MAJ(a,b,c);h=g;g=f;f=e;e=d2+t1;d2=c;c=b;b=a;a=t1+t2;}s[0]+=a;s[1]+=b;s[2]+=c;s[3]+=d2;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;}
void calc_sha256(const char*i,char*o){uint8_t d[64];uint32_t s[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};size_t l=strlen(i);memset(d,0,64);if(l>55)l=55;memcpy(d,i,l);d[l]=0x80;d[63]=(l*8)&0xFF;d[62]=((l*8)>>8)&0xFF;sha256_transform(s,d);for(int k=0;k<32;k++)sprintf(o+(k*2),"%02x",(s[k/4]>>(24-(k%4)*8))&0xFF);o[64]=0;}
void safe_flush(){int c;while((c=getchar())!='\n'&&c!=EOF);}

// === 3. 数据结构定义 (不可修改) ===

typedef struct {
    char sender[65];    // 发送方公钥
    char receiver[65];  // 接收方公钥
    double amount;      // 金额
    long timestamp;     // 时间戳
    char tx_id[65];     // 交易哈希ID
} Transaction;

typedef struct MinerNode {
    char name[32];      // 矿工/用户名称
    char pubkey[65];    // 公钥
    char privkey[65];   // 私钥
    struct MinerNode* next; // 链表指针
} MinerNode;

typedef struct Contact {
    char name[32];
    char pubkey[65];
    struct Contact* next;
} Contact;//定义用户名和公钥对照表

typedef struct {
    int index;
    char prev_hash[65];
    char merkle_root[65];
    long timestamp;
    int difficulty;
    long nonce;
    char miner_pubkey[65]; 
} BlockHeader;区块头

typedef struct Block {
    BlockHeader header;
    int tx_count;
    Transaction txs[MAX_TX_PER_BLOCK];
    char hash[65];
    struct Block* next; // 双向链表后继
    struct Block* prev; // 双向链表前驱
} Block;区块

// 全局变量 (组员需引用这些变量)
Block* g_head = NULL;       // 链表头
Block* g_tail = NULL;       // 链表尾
MinerNode* g_miner_head = NULL; // 矿工链表头
Contact* g_contact_head = NULL; // 联系人链表头
Transaction g_mempool[MEMPOOL_SIZE]; // 内存池数组
int g_mempool_count = 0;    // 内存池当前数量
time_t g_last_pack_time = 0; 

// 系统账号信息
char g_satoshi_priv[65] = {0}; char g_satoshi_pub[65] = {0};
char g_user_pubkey[65] = {0}; char g_user_privkey[65] = {0}; char g_user_name[32] = "GUEST";

// 预声明辅助函数 (已实现)
void save_miners(); void save_contacts(); void save_mempool();
void add_contact_manual(const char* n, const char* p); 

// ============================================================
// 🔽 组员协作区域 (请在此处开始编写)
// ============================================================

/* * 【MODULE A: 矿工与链表管理】
 * 任务：实现单向链表的插入与删除。
 * 知识点：头插法、指针操作、内存释放。
 */

// A1: 添加矿工 (头插法)
// 提示：1. malloc分配 MinerNode 2. 赋值 name/privkey 3. 用 calc_sha256 算 pubkey 4. 插入 g_miner_head
// 协同：完成后调用 add_contact_manual 同步到地址簿，调用 save_miners 保存。
void add_miner(const char* name, const char* privkey) {
    // TODO: 请实现代码
    // 伪代码:
    // node = malloc...
    // strcpy...
    // calc_sha256(privkey, node->pubkey)
    // node->next = g_miner_head; g_miner_head = node;
    // ...
}

// A2: 删除矿工 (链表删除)
// 提示：遍历链表找到名字匹配的节点，将其移出并 free。注意处理头节点删除的情况。
void delete_miner(const char* name) {
    // TODO: 请实现代码
    // 伪代码:
    // curr = g_miner_head; prev = NULL;
    // while(curr) {
    //    if match:
    //       if prev == NULL: g_miner_head = curr->next;
    //       else: prev->next = curr->next;
    //       free(curr); save_miners(); return;
    //    prev = curr; curr = curr->next;
    // }
}

// [A-加分项] 矿工排序 (Bonus)
// 提示：对 g_miner_head 链表按余额(需调用 get_balance)进行排序。
void sort_miners_by_balance() {
    // TODO: 选做
}


/* * 【MODULE B: 审计与查询】
 * 任务：遍历链表进行数据统计与查找。
 * 知识点：链表遍历、字符串比较、逻辑判断。
 */

// B1: 计算余额 (UTXO模型简化)
// 提示：从 g_head 遍历到 g_tail。对每个区块的每笔交易：
// 如果 receiver == pubkey -> 余额增加；如果 sender == pubkey -> 余额减少。
double get_balance(const char* pubkey) {
    double bal = 0.0;
    // TODO: 请实现代码
    // 伪代码:
    // Block* curr = g_head;
    // while(curr) {
    //    for i in txs:
    //       if tx.receiver == pubkey: bal += tx.amount
    //       if tx.sender == pubkey: bal -= tx.amount
    //    curr = curr->next;
    // }
    return bal;
}

// B2: 地址解析
// 提示：依次查找 g_contact_head 和 g_miner_head，如果名字匹配则返回公钥。
// 特殊处理：如果输入本身是64位Hash，直接返回；如果是 "SATOSHI"，返回 g_satoshi_pub。
const char* resolve_address(const char* input_name) {
    // TODO: 请实现代码
    return NULL; // 没找到返回NULL
}

// [B-加分项] 模糊查找 (Bonus)
// 提示：支持输入 "Sat" 就能返回 "SATOSHI" (使用 strncmp 或 strstr)。


/* * 【MODULE C: 调度与结构化】
 * 任务：管理交易池数组，生成默克尔根。
 * 知识点：数组队列操作、字符串拼接、Hash计算。
 */

// C1: 交易入池
// 提示：检查 g_mempool_count 是否已满。生成 Transaction 结构体，填入 g_mempool 数组。
// 必须生成 tx_id: calc_sha256(sender + receiver + amount + timestamp)
// 协同：完成后调用 save_mempool()。
void add_to_mempool(const char* sender, const char* receiver, double amount) {
    // TODO: 请实现代码
}

// C2: 计算默克尔根 (Merkle Root)
// 提示：将区块(b)内所有交易的 tx_id 拼接到一个长字符串 buffer 中。
// 然后对 buffer 做一次 calc_sha256，结果存入 b->header.merkle_root。
void calc_merkle_root(Block* b) {
    // TODO: 请实现代码
}

// [C-加分项] 优先打包 (Bonus)
// 提示：在入池或打包时，优先处理金额较大的交易 (排序 g_mempool)。


/* * 【MODULE D: 核心算法 (挖矿)】
 * 任务：组装区块头信息，进行工作量证明 (PoW)。
 * 知识点：暴力枚举、字符串格式化。
 */

// D1: 计算区块哈希
// 提示：将区块头的所有字段 (nonce, index, prev_hash...) 用 sprintf 拼成字符串。
// 注意：为了防止截断，建议把 nonce 放在字符串最前面。
void calc_block_hash(Block* b, char* out_hash) {
    // TODO: 请实现代码
    // sprintf(buf, "%ld%d%s...", b->header.nonce, b->header.index...);
    // calc_sha256(buf, out_hash);
}

// D2: 执行挖矿 (PoW)
// 提示：这是一个死循环。
// 1. 调用 calc_block_hash 算 hash。
// 2. 检查 hash 是否以 "000" 开头 (strncmp)。
// 3. 是 -> 成功，break；否 -> b->header.nonce++，继续算。
void perform_pow(Block* b) {
    // TODO: 请实现代码
}

// [D-加分项] 动态难度 (Bonus)
// 提示：传入难度参数，不再固定 "000"，而是根据参数判断前缀0的个数。


/* * 【MODULE E: 数据分析与递归】
 * 任务：实现递归资金溯源。
 * 知识点：递归函数、DFS思想。
 */

// E1: 递归溯源
// 提示：
// 1. 终止条件：b 为 NULL 或 depth > 8。
// 2. 遍历当前块交易，如果 tx.receiver == target：
//    打印 "收到 xxx 来自 sender"。
//    递归调用：recursive_trace(b->prev, tx.sender, depth + 1); // 追查钱是从哪来的
// 3. 递归调用：recursive_trace(b->prev, target, depth); // 继续在这个块之前的块里找 target 的收入
void recursive_trace(Block* b, const char* target, int depth) {
    // TODO: 请实现代码
}

// [E-加分项] 双向追踪 (Bonus)
// 提示：不仅追查“钱从哪来”，还能追查“钱去哪了”（需要向下遍历 next 指针）。


// ==========================================
// 7. 项目保留区域 (主逻辑与I/O，组员无需修改)
// ==========================================

// ... (此处省略 save/load 函数的具体实现，组长在集成时负责保留原代码) ...
// ... (此处省略 main 函数和菜单逻辑，组长负责保留) ...

// 占位函数：为了让空框架能编译，防止报错
// 组员实现相应模块后，这些占位符将被替换
// void save_miners() {} 
// void save_contacts() {}
// void save_mempool() {}
// void add_contact_manual(const char* n, const char* p) {}

// int main() {
//     printf("G6-Chain Collaboration Framework Loaded.\n");
//     printf("Please implement your modules.\n");
//     return 0;
// }
