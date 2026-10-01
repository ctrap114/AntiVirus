# ONNX 模型兼容性

Everbloom Security 的推理端使用 tract-onnx，输入仍然必须代表同一套恶意软件特征；它不是一个可以直接接受任意图像、字节序列或多输入模型的通用推理器。

## 当前适配范围

- 输入：单个数值张量。优先使用 ONNX 模型声明的静态 shape；动态 shape 会尝试 [N]、[1,N]、[N,1]、[1,N,1]、[1,1,N] 以及常见的 4-D singleton 布局。
- 输入 dtype：f16、f32、f64、有符号/无符号整数和 tract 支持的量化数值类型。Rust 侧生成的 f32 特征会在送入模型前转换。
- 特征：默认是 12 个规范化特征；模型目录可放置同名 features.json，内容为特征名数组，运行时按该顺序重排。
- 输出：数值张量可以是 f16/f32/f64、整数或量化类型；单值按 probability/logit 自动判断，多值按 probability 或 softmax 解码。
- 多输出：默认从第一个可解码输出开始尝试；可通过契约文件固定输出索引和恶意类别索引。

## 模型旁车契约

将 model_contract.json 放在 ONNX 文件同一目录。例如：

    {
      "output_index": 1,
      "malicious_index": 2,
      "output_kind": "logit"
    }

output_kind 可取 auto、probability 或 logit。二分类默认恶意类别为索引 1，多分类默认使用最后一个类别；类别定义不符合该约定时必须设置 malicious_index。

## 仍不兼容的情况

当前扫描器不自动填充多输入模型、不执行图像/音频/原始 token 化预处理，也不会猜测模型需要的标准化均值方差。此类模型应先导出一个单输入特征适配器，或在 Rust 侧增加明确的预处理实现。

加载日志会打印模型的输入/输出数量、dtype 和 shape。接入第三方模型时，应先确认：

1. 训练特征与 features.json 的顺序完全一致；
2. 输入张量元素总数与特征数量一致；
3. 输出的类别顺序、probability/logit 语义与契约文件一致；
4. 在干净样本、已知恶意样本和变形样本上分别验证误报、漏报和阈值。
