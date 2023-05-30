// 节点类型
type Type =
  // 未知，不可列出，初始状态
  | 'non-readable'
  // 可回收，无意义
  | 'recyclable'
  // 目录，可进入下一层
  | 'directory'
  // 自述文件，获得本层所有类型可执行文件行为的信息
  | 'readme'
  // 可选的系统接入点，必定为可回收
  | 'entry'
  & Executable

// 可执行节点类型
// 可执行节点被转变后可以被通过
type Executable =
  // 守护进程，可耗费处理器资源使其停止、强制重新启动
  // 但若是互锁进程则在 x 个处理器时间单位后被重启，具体取决于优先级(敏捷)数值和类型(钩子重启或定时重启)
  // 可耗费额外处理器时间覆写使其失效或转变，均存在成功几率
  | 'daemon'
  // 防火墙，可耗费大量处理器资源使其停止、强制重新启动
  // 可耗费额外处理器时间覆写使其失效或转变，均存在成功几率
  | 'firewall'
  // 反制软件，可耗费处理器资源使其停止、强制重新启动
  // 用户对任何节点提升优先级、停止或强制重新启动、覆写的行为都会提升探测等级或威胁等级
  // 可在探测等级升高后发现用户并执行特征分析(标记)，提升每个行为增加的威胁等级
  // 若报警等级过高可能导致节点在倒计时后关闭，如果发生则会在 x 秒后被人工介入，任务失败
  // 可耗费大量处理器资源覆写使之失效或转变，均存在成功几率
  // 可下载并反编译，但必须在节点失效后进行
  | 'counter-measure'
  // 未知可执行服务，需要耗费处理器资源使其停止、强制重新启动
  // 行为可能发生转变
  // 可耗费额外处理器时间覆写使其失效或转变，均存在成功几率
  | 'undefined'

// 行为类型
type Action = {
  type:
    | 'stop'
    | 'force-restart'
    | 'overwrite-disable'
    // 覆写并改变行为，使其对用户友好
    | 'overwrite-alter-behavior'
    // 覆写，使用户可以通过
    | 'overwrite-alter-relay'
    // 覆写并干扰其正常运作，持续 x 回合，仅限可执行文件
    | 'overwrite-jam'
    // 分析目标节点，减少其他所有行为的消耗时间
    | 'analyze'
  // 开销时间
  // 若开销时间过大，可能需要等待至下一个事件循环，取决于节点定义及用户能力
  timeCost: ((factor: {base: number, analyzeCount: number}) => number),
  // 成功率，范围 0-1，取决于节点定义及用户能力
  successRate: number | ((factor: {base: number, retryCount: number}) => number),
}

type Objective =
  | 'download'
  | 'overwrite'

export type Node<T extends Type, O extends Objective | undefined> = {
  type: T,
  // 节点描述，没有则继承此类节点默认描述
  desc?: string,
  actions: Action[],
  // 优先级(敏捷值)，该值越大越先执行，仅可执行文件有此属性
  priority?: T extends Executable ? number : never,
  // 该节点上的任务目标
  objective?: O,
  // 任务目标描述
  objectiveDesc?: O extends Objective ? string : never,
  // 该任务目标需要分析才能发现
  requireAnalysis?: O extends Objective ? true : never,
  // 该任务目标为主要任务目标
  isPrimary?: O extends Objective ? true : never,
  // 守护进程监视的节点，每一轮事件循环后结算
  watch?: {
    node: T extends 'daemon' ? Node<any, any> : never
    type:
      // 保证节点不变及激活
      | 'signature'
      // 保证节点存在及激活
      | 'active'
  }
  // 反制措施分析用户后增加的威胁点数, 0-5，0 代表没有主动分析能力
  analysisStrength?: T extends 'counter-measure' ? number : never,
}
