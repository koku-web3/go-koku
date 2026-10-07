# Vault接入AWS身份认证
## Hashicorp Vault的身份认证
在 Vault 中，Authentication（认证方法） 是一种让用户/服务向 Vault 证明自己身份的机制。Vault 都会在请求处理过程中强制执行身份验证。大多数情况下，Vault 会将身份验证管理和决策委托给相关的已配置外部身份验证方法（例如，Amazon Web Services、GitHub、Google Cloud Platform、Kubernetes、Microsoft Azure、Okta 等）。

下面介绍通过接入 AWS IAM 身份认证方法，主要是在 AWS 创建`Role`、`User`和`策略`三个对象，其中需要`User`是因为我们部署的环境不一定是在 AWS EC2 上，所以需要`User`的`access_key`和`secret_key`使用一个固定的访问通道来调用 AWS API。

## 1. 创建IAM Role

**1.1 在 IAM 控制台点击左侧 Roles（角色） -> Create role（创建角色）**

**1.2 选择可信实体**

因为我们的服务暂时不打算部署在 EC2，而是计划用 AWS Access Key 模拟，所以选择 **AWS 账户** -》 此账户。

**1.3 角色详情**

输入角色名称：`vault@create-key-role`。


**1.4 点击“创建角色”**

创建完成后，进入该角色详情页，复制并记录下该角色的 ARN，格式形如：`arn:aws:iam::<AWS账户ID>:role/vault@create-key-role`。

**1.5 创建第2个角色**

按照上面步骤，再创建另一个角色，名称：`vault@signer-role`。

这时得到两个 ARN：
- 用于创建密钥：`arn:aws:iam::<AWS账户ID>:role/vault@create-key-role`。
- 用于签名：`arn:aws:iam::<AWS账户ID>:role/vault@signer-role`。


## 2. 创建策略

**2.1 点击“创建策略”按钮**

**2.2 点击 JSON**

**2.3 输入策略内容**

创建一个名为 `VaultAuthenticatePolicy` 的策略
``` json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": [
                "arn:aws:iam::<AWS账户ID>:role/vault@create-key-role",
                "arn:aws:iam::<AWS账户ID>:role/vault@signer-role"
            ]
        }
    ]
}
```

## 3. 创建 IAM User

**3.1 在 IAM 控制台点击左侧 IAM 用户 -> Create User（创建用户）**

**3.2 指定用户详细信息**
- 用户名输入：`user-vault-visitor`
- "向用户提供 AWS 管理控制台的访问权限"：不需要勾选
- 下一步

**3.3 设置权限**
- 选择“直接附加策略” 
- 在“权限策略” 搜索框输入 `VaultAuthenticatePolicy`（即上面已经创建过的策略）
- 勾选结果
- 下一步

**3.4 赋予获取 Role 的权限**
- 左侧菜单选择 "用户"（Users） → 找到用户 "user-vault-visitor"
- 添加内联策略
  - 点击用户名 user-vault-visitor 进入详情页
  - 选择 "权限"（Permissions） 标签
  - 点击 "添加内联策略"（Add inline policy）
- 创建策略 
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iam:GetRole",
            "Resource": ["arn:aws:iam::<AWS账户ID>:role/vault@create-key-role","arn:aws:iam::<AWS账户ID>:role/vault@signer-role"]
        }
    ]
}
```
- 保存策略，输入名称`AllowGetRoleForVault`

**3.5 查看用户**
- 点击上面创建好的用户
- 创建访问密钥
- 选择“本地”

得到用户的 `access_key`和`secret_key`
