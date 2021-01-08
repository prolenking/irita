<!--
order: 1
-->

# 边缘计算服务

## 概念

- 边缘计算服务通过为 IRITA 提供边缘计算能力，从而为链外服务与 IRITA 的高效交互赋能。边缘计算作为 IRITA 可信计算的重要补充，极大地提高了平台的计算效率以及可扩展性。

- 边缘计算服务能够对数据进行预处理，包括身份核验、有效性检查，以及对交易的排序、聚合、缓存与过滤。另外，边缘计算服务针对多种场景进行建模，满足典型应用的数据处理需求。

## 架构

边缘计算服务采用分层架构，主要分为服务层、应用层以及链上交互层。

- 服务层是边缘计算服务的入口，链外服务通过此接口与其进行交互。服务层将不同的服务请求路由至相应的应用处理器。

- 应用层负责业务逻辑处理。应用层包含多个应用处理器，每个处理器由若干预定义的计算单元组成。这些计算单元构成一个管道，对数据进行渐进处理。

- 链上交互层将预处理之后的链外请求构造成区块链交易，发布到 IRITA 链上完成共识, 并获取交易处理结果。

- 可以通过开发适配器为边缘计算服务定制应用处理逻辑，使得边缘计算服务能够方便地扩展到各种应用场景。