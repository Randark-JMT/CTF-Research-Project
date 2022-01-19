# 针对wasm二进制文件的逆向分析

> 近几年针对wasm二进制文件的逆向分析已经愈发常见，那么re方向的选手也应该跟随潮流，及时去针对wasm方向去学习相应的知识和搜集对应的工具

## 简介

[WebAssembly官方网址](https://www.wasm.com.cn/)     

[Wasm代码在线编译生成-WebAssembly Explorer](https://mbebenita.github.io/WasmExplorer/)     

[Wasm代码编译与逆汇编 Wabt](https://github.com/WebAssembly/wabt)

这里先贴上WebAssembly官方对于wasm技术的描述：**WebAssembly 是一个可移植、体积小、加载快并且兼容 Web 的全新格式**

另外，也顺便贴上wasm的四大优点：

> **高效**
> WebAssembly 有一套完整的语义，实际上 wasm 是体积小且加载快的二进制格式， 其目标就是充分发挥硬件能力以达到原生执行效率
> 
> **安全**
> WebAssembly 运行在一个沙箱化的执行环境中，甚至可以在现有的 JavaScript 虚拟机中实现。在web环境中，WebAssembly将会严格遵守同源策略以及浏览器安全策略。
> 
> **开放**
> WebAssembly 设计了一个非常规整的文本格式用来、调试、测试、实验、优化、学习、教学或者编写程序。可以以这种文本格式在web页面上查看wasm模块的源码。
> 
> **标准**
> WebAssembly 在 web 中被设计成无版本、特性可测试、向后兼容的。WebAssembly 可以被 JavaScript 调用，进入 JavaScript 上下文，也可以像 Web API 一样调用浏览器的功能。当然，WebAssembly 不仅可以运行在浏览器上，也可以运行在非web环境下。

那么，凡是安全性好的技术，都意味着分析难度大，并且会极大概率移植进CTF的比赛，毕竟CTF的比赛就是针对网络安全性的比赛。

~~***也就是对选手极其不友好***~~

可以明白，wasm的意义基本就是实现了对于网页动态性能的极大提高，摆脱了云端性能不足导致客户端体验不佳的情况，那么可以预想到未来的web环境中WebAssembly将会占有很大的一个部分。那么在CTF中也将实现Reverse和Web两个方向的有机结合（）

针对wasm的逆向工具目前还寥寥无几，也就意味着当前针对wasm的逻辑分析，重心将放在基于浏览器的动态调试，而不是静态分析。当然，目前wasm的静态分析是可行的，但是效率还远远不如直接动态调试。（但是往往由于网页元素复杂，你连断点应该下在哪里都找不到）

同时，WebAssembly作为一种崭新的，兼容性极强的全新格式，它被广泛吸收并在多个开发框架中得到支持。例如Javascript、Unity、WebGL和Go等等。也就意味着在进行Wasm逆向分析的时候，还要多方面地对其中所用到的框架进行综合分析。应当注意，有时候题目会涉及到Wasm，但是对于数据处理的部分却不是在Wasm中，而是在Js，或者其他框架内。例如，当网站使用UnityWeb和WebAssembly构建的时候，Wasm可能只是障眼法，而数据处理部分却放在了UnityWeb之中，这样便加大了选手在处理数据逻辑时的难度。选手这时就应该同步对UnityWeb中的数据流和WebAssemly的数据流进行分析（一般这个时候这个题目到最后都是0解了）。

## 静态分析

在尝试静态分析的时候，往往离不开[Wabt](https://github.com/WebAssembly/wabt)这个工具。wabt是WebAssembly官方提供的针对wasm文件的分析框架，可以将wasm文件转换为.wat文件，或者进一步逆向为.c和.h文件，以方便二次编译后使用其它自动静态分析工具来分析。当然，目前Wasm文件逆向出的.c文件常常会突破百兆大关，而编译后的.o文件往往也不会好到哪去。这就意味着对于主流静态分析工具（如IDA）来说，分析时间，分析难度，以及分析失败的概率，都将大大提高。这时候就要灵活使用其它手段，例如使用内存分析工具，如 Il2cppdumper ，或者直接放弃，因为根据目前的赛事情况，一旦涉及WebAssembly和其它框架一同构建的网站的时候，选手不知道怎么做，出题人也不知道怎么做（

## 动态调试

### [ISCTF-easy_wasm](https://github.com/f00001111/ISCTF2021/tree/main/Reverse/easy_wasm)

在官方解答中，是采用了基于`wasm2c`这个工具实现了.wasm文件逆向出.c文件，再编译出.o这种IDA可以直接分析的二进制文件，这种解法可以在我的wp:[Randark_JMT-easy_wasm](https://randark.site/2021/11/07/easy_wasm/)这里查看详细步骤。在这里，我重点将放在如何运用浏览器来针对wasm程序进行逻辑分析：

#### 0x01 启动本地环境

在网页根目录，通过Python启动http：

```powershell
python -m http.server 8080
```

然后通过浏览器访问：

```text
http://localhost:8080
```

便可以通过本地映射访问到环境。

#### 0x02 下断点，观察数据

#### 0x03 猜测数据意义

#### 0x04 尝试分析逻辑

#### 0x05 校验答案按
