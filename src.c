/*
 * G6-Chain 分布式协作开发框架 (Team Version)
 * ================================================================================================
 * 【项目说明】
 * 本项目是一个基于C语言的区块链模拟系统。
 * 项目已预置：系统架构、加密库、文件存储、UI交互，主函数。
 * 组员需完成：核心数据结构与算法逻辑 (见下方 MODULE A - E)。
 *
 * 【开发指南】
 * 1. 搜索 "MODULE X" (X是你选择的模块，如 MODULE A)。
 * 2. 阅读注释中的 "任务目标" 和 "实现提示"。
 * 3. 删除临时的 return 语句，编写你的逻辑。
 * 4. 尽可能尝试 "加分拓展项"。
 * 5.！确保你的工作分支正确，每个人 使用一个分支开发自己的模块，可以添加函数或参数，但是非必要不修改基础配置。
 * 6.第六个部分是我们协作开发的部分！不看错改错，会有对应的标注；
 * =================================================================================================
 */
//MODULE A  徐廷瀚
//MODULE B	董毅
//MODULE C	张宗烜
//MODULE D	游骏宏
//MODULE E	李易章

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

// 兼容性处理：Windows系统特有的API调用
#ifdef _WIN32
#include <windows.h>
#endif

// === 1. 配置宏定义 (系统参数) ===
// 数据持久化文件名定义
#define CHAIN_FILE   "blockchain.dat" // 区块链账本文件
#define MINER_FILE   "miners.dat"     // 矿工私钥数据库 (模拟本地钱包)
#define CONTACT_FILE "contacts.dat"   // 地址簿 (用户名->公钥映射)
#define MEMPOOL_FILE "mempool.dat"    // 待打包交易池缓存

// 区块链参数
#define MAX_TX_PER_BLOCK 10  // 每个区块最大包含交易数
#define MEMPOOL_SIZE 100     // 内存池最大容量
#define BLOCK_INTERVAL 10    // 自动出块间隔 (秒)

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

// === 3. 数据结构定义  ===

// [数据结构] 交易实体
typedef struct {
    char sender[65];    // 发送方公钥
    char receiver[65];  // 接收方公钥
    double amount;      // 交易金额
    long timestamp;     // 交易生成时间
    char tx_id[65];     // 交易唯一标识 (TxHash)
} Transaction;

// [数据结构] 矿工节点 (单向链表)
// 用于存储拥有挖矿权限的用户
typedef struct MinerNode {
    char name[32];      // 矿工名称
    char pubkey[65];    // 公钥 (钱包地址)
    char privkey[65];   // 私钥 (密码生成的Hash)
    struct MinerNode* next; // 指向下一个矿工
} MinerNode;

// [数据结构] 联系人节点 (单向链表)
// 相当于系统的全局“地址簿”
typedef struct Contact {
    char name[32];      // 用户名
    char pubkey[65];    // 公钥
    struct Contact* next;
} Contact;


// [数据结构] 区块头 (元数据)
typedef struct {
    int index;              // 区块高度 (第几个块)
    char prev_hash[65];     // 前一个区块的 Hash (链式结构的指针)
    char merkle_root[65];   // 默克尔根 (交易集合的指纹)
    long timestamp;         // 出块时间
    int difficulty;         // 挖矿难度
    long nonce;             // 随机数 (PoW 的答案)
    char miner_pubkey[65];  // 谁挖出来的 (用于奖励)
} BlockHeader;

// [数据结构] 区块 (双向链表)
// 整个区块链的核心载体
typedef struct Block {
    BlockHeader header;
    int tx_count;
    Transaction txs[MAX_TX_PER_BLOCK]; // 交易列表 (定长数组)
    char hash[65];                     // 当前区块的 Hash
    struct Block* next; // 指向下一个块 (未来)
    struct Block* prev; // 指向上一个块 (历史) - 用于回溯
} Block;

// 4.===全局变量 (组员需引用这些变量)===
Block* g_head = NULL;           // 区块链头指针
Block* g_tail = NULL;           // 区块链尾指针 (最新块)
MinerNode* g_miner_head = NULL; // 矿工列表头指针
Contact* g_contact_head = NULL; // 地址簿头指针
Transaction g_mempool[MEMPOOL_SIZE]; // 交易内存池 (数组模拟队列)
int g_mempool_count = 0;        // 当前待打包交易数
time_t g_last_pack_time = 0;    // 上次自动打包的时间


// 系统账号信息
char g_satoshi_priv[65] = {0}; char g_satoshi_pub[65] = {0}; // 中本聪账号
char g_user_pubkey[65] = {0}; char g_user_privkey[65] = {0}; // 当前用户密钥
char g_user_name[32] = "GUEST"; // 当前用户名

// 预声明辅助函数 (已实现)
void save_miners(); void save_contacts(); void save_mempool();
void add_contact_manual(const char* n, const char* p); 

// 5. ===持久化层 (I/O) - 负责数据的存取==

// 保存内存池数据 (防止程序关闭后未打包的交易丢失)
void save_mempool() {
    FILE* fp = fopen(MEMPOOL_FILE, "wb");
    if(!fp) return;
    fwrite(&g_mempool_count, sizeof(int), 1, fp);
    if(g_mempool_count > 0) fwrite(g_mempool, sizeof(Transaction), g_mempool_count, fp);
    fclose(fp);
}

// 加载内存池数据
void load_mempool() {
    FILE* fp = fopen(MEMPOOL_FILE, "rb");
    if(!fp) return;
    int count = 0;
    if(fread(&count, sizeof(int), 1, fp)) {
        if(count > MEMPOOL_SIZE) count = MEMPOOL_SIZE; // 边界保护
        g_mempool_count = count;
        if(count > 0) fread(g_mempool, sizeof(Transaction), count, fp);
    }
    fclose(fp);
}

// 保存地址簿 (Contact链表 -> 文件)
void save_contacts() {
    FILE* fp = fopen(CONTACT_FILE, "wb");
    if(!fp) return;
    Contact* curr = g_contact_head;
    while(curr) {
        fprintf(fp, "%s %s\n", curr->name, curr->pubkey);
        curr = curr->next;
    }
    fclose(fp);
}

// 检查地址簿中是否已存在某用户名 (查找算法)
int contact_exists(const char* name) {
    Contact* curr = g_contact_head;
    while(curr) {
        if(strcmp(curr->name, name) == 0) return 1;
        curr = curr->next;
    }
    return 0;
}

// 检查是否已经是矿工
int is_miner(const char* name) {
    MinerNode* curr = g_miner_head;
    while(curr) {
        if(strcmp(curr->name, name) == 0) return 1;
        curr = curr->next;
    }
    return 0;
}

// 加载地址簿 (文件 -> Contact链表)
// 包含去重逻辑，防止重复加载
void load_contacts() {
    FILE* fp = fopen(CONTACT_FILE, "rb");
    if(!fp) return;
    char name[32], pub[65];
    while(fscanf(fp, "%s %s", name, pub) != EOF) {
        if(contact_exists(name)) continue; // 关键：去重
        Contact* node = (Contact*)malloc(sizeof(Contact));
        strcpy(node->name, name);
        strcpy(node->pubkey, pub);
        // 头插法插入链表
        node->next = g_contact_head;
        g_contact_head = node;
    }
    fclose(fp);
}

// 保存矿工列表
void save_miners() {
    FILE* fp = fopen(MINER_FILE, "wb");
    if(!fp) return;
    MinerNode* curr = g_miner_head;
    while(curr) {
        fprintf(fp, "%s %s\n", curr->name, curr->privkey);
        curr = curr->next;
    }
    fclose(fp);
}

// 加载矿工列表
void load_miners() {
    FILE* fp = fopen(MINER_FILE, "rb");
    if(!fp) return;
    char name[32], priv[65];
    while(fscanf(fp, "%s %s", name, priv) != EOF) {
        if(is_miner(name)) continue; // 去重
        MinerNode* node = (MinerNode*)malloc(sizeof(MinerNode));
        strcpy(node->name, name);
        strcpy(node->privkey, priv);
        calc_sha256(priv, node->pubkey); // 重新计算公钥
        node->next = g_miner_head;
        g_miner_head = node;
    }
    fclose(fp);
}

// 保存区块链数据
void save_chain() {
    FILE* fp = fopen(CHAIN_FILE, "wb");
    if(!fp) return;
    Block* curr = g_head;
    while(curr) {
        fwrite(curr, sizeof(Block), 1, fp); // 直接二进制写入整个结构体
        curr = curr->next;
    }
    fclose(fp);
}

// 加载区块链数据 (重建双向链表)
void load_chain() {
    FILE* fp = fopen(CHAIN_FILE, "rb");
    if(!fp) return;
    g_head = NULL; g_tail = NULL;
    Block temp;
    Block* last = NULL;
    int count = 0;
    // 循环读取结构体块
    while(fread(&temp, sizeof(Block), 1, fp)) {
        Block* node = (Block*)malloc(sizeof(Block));
        *node = temp;
        // 重建指针关系 (因为文件里存的指针地址是无效的)
        node->next = NULL;
        node->prev = last;
        if(g_head == NULL) g_head = node;
        else last->next = node;
        last = node;
        count++;
    }
    g_tail = last;
    fclose(fp);
}


// ============================================================
// 🔽 6.组员协作区域 (请在此处开始编写)--核心业务逻辑层
// ============================================================

/* * 【MODULE A: 矿工与链表管理】----徐廷瀚
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



/* * 【MODULE B: 审计与查询】---董毅
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


/* * 【MODULE C: 调度与结构化】---张宗烜
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




/* * 【MODULE D: 核心算法 (挖矿)】---游骏宏
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



/* * 【MODULE E: 数据分析与递归】---李易章
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






//】=========================
//7.UI与交互(User Interface)
//==========================

// 格式化打印时间戳
void print_time(long timestamp) {
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    char buffer[26];
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    printf("%s", buffer);
}

// 显示所有已注册用户
void show_registered_users() {
    printf("\n === 已注册用户列表 ===\n");
    printf(" %-15s | %-15s | %-66s\n", "用户名", "余额", "公钥地址");
    printf(" ---------------------------------------------------------------------------------------------------\n");
    Contact* curr = g_contact_head;
    int count = 0;
    while(curr) {
        printf(" %-15s | %-15.2f | %s\n", curr->name, get_balance(curr->pubkey), curr->pubkey);
        curr = curr->next;
        count++;
    }
    printf(" ---------------------------------------------------------------------------------------------------\n");
    printf(" 共 %d 位用户。\n", count);
}

// 显示单个区块详情
void show_block_detail(int index) {
    Block* curr = g_head;
    while(curr) {
        if(curr->header.index == index) {
            printf("\n === 区块 #%d 详情 ===\n", index);
            printf(" Hash     : %s\n", curr->hash);
            printf(" PrevHash : %s\n", curr->header.prev_hash);
            printf(" Miner    : %s (%.16s...)\n", 
                   resolve_name_by_pubkey(curr->header.miner_pubkey), curr->header.miner_pubkey);
            printf(" Time     : "); print_time(curr->header.timestamp); printf("\n");
            printf(" Nonce    : %ld\n", curr->header.nonce);
            printf(" ---------------------------------------------------\n");
            for(int i=0; i<curr->tx_count; i++) {
                const char* s_name = resolve_name_by_pubkey(curr->txs[i].sender);
                const char* r_name = resolve_name_by_pubkey(curr->txs[i].receiver);
                printf("   [%d] %-10s -> %-10s : %-10.2f (Time: ", i, s_name, r_name, curr->txs[i].amount);
                print_time(curr->txs[i].timestamp);
                printf(")\n");
            }
            return;
        }
        curr = curr->next;
    }
    printf(" [错误] 未找到区块。\n");
}

// 可视化打印链条结构
void show_visual_chain() {
    Block* curr = g_head;
    printf("\n [链条] ");
    while(curr) {
        printf("[#%d|%.4s..]", curr->header.index, curr->hash);
        if(curr->next) printf("->");
        curr = curr->next;
    }
    printf("\n");
}

// [核心算法] 递归资金溯源 (Recursive Trace)
// target: 要查询的人
// depth: 当前递归深度 (防止死循环)
void recursive_trace(Block* b, const char* target, int depth) {
    // 终止条件：到达创世块前 或 深度过大
    if(!b || depth > 8) return;
    
    // 在当前区块中查找 target 的入账记录
    for(int i=0; i<b->tx_count; i++) {
        if(strcmp(b->txs[i].receiver, target) == 0) {
            const char* sender_name = resolve_name_by_pubkey(b->txs[i].sender);
            printf("  [溯源] 层级-%d: 收到 %.2f (来自: %s)\n", 
                depth, b->txs[i].amount, sender_name);
            
            // 递归点：如果发送者不是系统，继续查发送者的钱是哪来的
            if(strcmp(b->txs[i].sender, "SYSTEM") != 0 && strcmp(b->txs[i].sender, "SYSTEM_REWARD") != 0) {
                recursive_trace(b->prev, b->txs[i].sender, depth + 1);
            }
        }
    }
    // 继续向前一个区块查找
    recursive_trace(b->prev, target, depth);
}

// [UI交互] 矿工管理菜单
void miner_menu() {
    int choice;
    char name[32], priv[65];
    char temp_priv[65], temp_pub[65];
    
    while(1) {
        auto_mine_check(); // 保持后台挖矿检测
        printf("\n === 矿工管理 ===\n");
        printf(" 1. 查看列表\n");
        printf(" 2. 添加矿工 (新用户/升级现有用户)\n");
        printf(" 3. 删除矿工\n");
        printf(" 0. 返回\n");
        printf(" 请输入: ");
        if(scanf("%d", &choice)!=1) { safe_flush(); continue; }
        safe_flush();
        
        if(choice == 0) break;
        if(choice == 1) {
            MinerNode* curr = g_miner_head;
            printf("\n %-10s | %-10s\n", "姓名", "余额");
            while(curr) {
                printf(" %-10s | %-10.2f\n", curr->name, get_balance(curr->pubkey));
                curr = curr->next;
            }
        }
        else if(choice == 2) {
            // 添加矿工逻辑：解决注册冲突
            printf(" 名称: "); scanf("%s", name);
            if(is_miner(name)) {
                printf(" [错误] 该用户已经是矿工了！\n");
                continue;
            }

            printf(" 私钥/密码: "); scanf("%s", priv); safe_flush();
            // 统一使用 SHA256 派生公私钥
            calc_sha256(priv, temp_priv); // 密码->私钥
            calc_sha256(temp_priv, temp_pub); // 私钥->公钥

            const char* exist_pub = resolve_address(name);
            if(exist_pub != NULL) {
                // 情况1: 用户已存在，验证密码是否匹配
                if(strcmp(exist_pub, temp_pub) == 0) {
                    printf(" [验证成功] 将现有用户 %s 升级为矿工。\n", name);
                    add_miner_node(name, temp_priv);
                } else {
                    printf(" [错误] 用户已存在，但密码(私钥)不匹配！无法添加。\n");
                }
            } else {
                // 情况2: 新用户，直接添加
                printf(" [成功] 新建矿工 %s。\n", name);
                add_miner_node(name, temp_priv);
                add_contact_manual(name, temp_pub);
            }
        }
        else if(choice == 3) {
            printf(" 要删除的矿工名称: "); scanf("%s", name); safe_flush();
            delete_miner(name);
        }
    }
}

// [UI交互] 区块浏览器菜单
void explorer_menu() {
    int choice, idx;
    char target[100];
    while(1) {
        auto_mine_check();
        printf("\n === 区块浏览器 ===\n");
        printf(" 1. 可视化链条\n");
        printf(" 2. 区块详情 (优化版)\n");
        printf(" 3. 资金溯源\n");
        printf(" 0. 返回\n");
        printf(" 请输入: ");
        if(scanf("%d", &choice)!=1) { safe_flush(); continue; }
        safe_flush();
        if(choice == 0) break;
        if(choice == 1) show_visual_chain();
        else if(choice == 2) {
            printf(" 高度: "); scanf("%d", &idx);
            show_block_detail(idx);
        }
        else if(choice == 3) {
            printf(" 目标(名字/公钥): "); scanf("%s", target);
            const char* addr = resolve_address(target);
            if(addr) {
                printf(" [系统] 解析地址为: %.16s...\n", addr);
                recursive_trace(g_tail, addr, 1);
            } else {
                printf(" [错误] 未知用户。\n");
            }
        }
    }
}

// 初始化默认矿工 (演示用)
void init_default_miners() {
    if(g_miner_head == NULL) {
        char p[65];
        // 预设三个矿工，密码分别为 secret_a/b/c
        calc_sha256("secret_a", p); add_miner_node("Miner_A", p); add_contact_manual("Miner_A", g_miner_head->pubkey);
        calc_sha256("secret_b", p); add_miner_node("Miner_B", p); add_contact_manual("Miner_B", g_miner_head->pubkey);
        calc_sha256("secret_c", p); add_miner_node("Miner_C", p); add_contact_manual("Miner_C", g_miner_head->pubkey);
    }
}

// [UI交互] 登录界面
void login_screen() {
    char input[100];
    int choice;
    char temp_priv[65];
    char temp_pub[65];
    
    printf("\n === G6-Chain User System ===\n");
    printf(" 1. 登录中本聪账号 (Satoshi)\n");
    printf(" 2. 注册/登录普通账号\n");
    printf(" 请选择: ");
    scanf("%d", &choice); safe_flush();
    
    if(choice == 1) {
        strcpy(g_user_privkey, g_satoshi_priv);
        strcpy(g_user_pubkey, g_satoshi_pub);
        strcpy(g_user_name, "SATOSHI");
    } else {
        while(1) {
            printf(" 请输入用户名: "); scanf("%s", g_user_name);
            int exists = contact_exists(g_user_name);
            printf(" 请输入密码: "); scanf("%s", input); safe_flush();
            calc_sha256(input, temp_priv);
            calc_sha256(temp_priv, temp_pub);
            
            if(exists) {
                // 登录验证逻辑
                const char* stored_pub = resolve_address(g_user_name);
                if(stored_pub && strcmp(stored_pub, temp_pub) == 0) {
                    printf(" [欢迎回来] 登录成功！\n");
                    strcpy(g_user_privkey, temp_priv);
                    strcpy(g_user_pubkey, temp_pub);
                    break;
                } else {
                    printf(" [错误] 密码错误！\n");
                }
            } else {
                // 注册逻辑
                printf(" [新用户] 注册成功！\n");
                strcpy(g_user_privkey, temp_priv);
                strcpy(g_user_pubkey, temp_pub);
                add_contact_manual(g_user_name, g_user_pubkey);
                break;
            }
        }
    }
    printf("\n [当前用户] %s\n", g_user_name);
    printf(" 公钥: %s\n", g_user_pubkey);
    printf(" 余额: %.2f\n", get_balance(g_user_pubkey));
}



// ==========================================
// 8. 项目保留区域 (主函数与I/O，组员无需修改)随时更新.....
// ==========================================

int main() {
    // 1. Windows 路径与编码修复
    // 强制设置工作目录为 EXE 所在目录，解决双击运行时找不到文件的问题
    #ifdef _WIN32
    char exe_path[MAX_PATH];
    GetModuleFileName(NULL, exe_path, MAX_PATH);
    char *last_slash = strrchr(exe_path, '\\');
    if (last_slash) *last_slash = '\0';
    SetCurrentDirectory(exe_path);
    system("chcp 65001 > nul"); // 设置控制台为 UTF-8 防止中文乱码
    #endif
    
    // 2. 初始化设置
    setbuf(stdout, NULL); // 禁用输出缓存，防止 printf 不显示
    srand(time(NULL));    // 随机数种子初始化

    // 3. 加载持久化数据 (顺序重要)
    load_chain();    // 加载区块链
    load_contacts(); // 加载地址簿
    load_miners();   // 加载矿工
    load_mempool();  // 加载未打包交易

    // 4. 首次运行初始化
    init_genesis();        // 如果没有区块链，创建创世块
    init_default_miners(); // 如果没有矿工，创建默认矿工

    // 5. 进入登录流程
    login_screen();

    // 6. 主功能循环
    int choice;
    char recv_name[100];
    double amount;

    while(1) {
        auto_mine_check(); // 每次循环都检查是否需要挖矿

        printf("\n ========== 主菜单 ==========\n");
        printf(" 1. 发起转账 (支持用户名)\n");
        printf(" 2. 区块浏览器 (含溯源)\n");
        printf(" 3. 矿工管理\n");
        printf(" 4. 刷新状态\n");
        printf(" 5. 查看已注册用户\n"); 
        printf(" 0. 退出\n");
        printf(" 请输入: ");
        
        if(scanf("%d", &choice) != 1) { safe_flush(); continue; }
        safe_flush();

        switch(choice) {
            case 1:
                printf(" 接收方(如 Miner_A / SATOSHI): "); 
                scanf("%s", recv_name); safe_flush();
                printf(" 金额: "); 
                scanf("%lf", &amount); safe_flush();
                
                // 解析接收方地址
                const char* addr = resolve_address(recv_name);
                if(addr == NULL) {
                    printf(" [错误] 未知用户，请输入完整公钥。\n");
                } else {
                    if(get_balance(g_user_pubkey) < amount) printf(" [错误] 余额不足!\n");
                    else add_to_mempool(g_user_pubkey, addr, amount);
                }
                break;
            case 2: explorer_menu(); break;
            case 3: miner_menu(); break;
            case 4: 
                printf(" 当前余额: %.2f\n", get_balance(g_user_pubkey));
                printf(" 内存池等待: %d 笔\n", g_mempool_count);
                break;
            case 5: show_registered_users(); break;
            case 0: return 0;
            default: printf(" 无效指令\n");
        }
    }
    return 0;
}