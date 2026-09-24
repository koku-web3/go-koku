
# PROTOC
**生成`signer`项目 .pd.go 文件**
``` bash
protoc --go_out=. \
       --go_opt=Mproto/signer.proto=./pkg/proto/signer \
       --go-grpc_out=. \
       --go-grpc_opt=Mproto/signer.proto=./pkg/proto/signer \
       proto/signer.proto
```

**生成`key-creator`项目 .pd.go 文件**
``` bash
protoc --go_out=. \
       --go_opt=Mproto/keycreator.proto=./pkg/proto/key-creator \
       --go-grpc_out=. \
       --go-grpc_opt=Mproto/keycreator.proto=./pkg/proto/key-creator \
       proto/keycreator.proto
```

**生成`coordinator`项目 .pd.go 文件**
``` bash
protoc --go_out=. \
       --go_opt=Mproto/coordinator.proto=./pkg/proto/coordinator \
       --go-grpc_out=. \
       --go-grpc_opt=Mproto/coordinator.proto=./pkg/proto/coordinator \
       proto/coordinator.proto
```

**生成`txbuilder`项目 .pd.go 文件**
``` bash
protoc --go_out=. \
       --go_opt=Mproto/txbuilder.proto=./pkg/proto/txbuilder \
       --go-grpc_out=. \
       --go-grpc_opt=Mproto/txbuilder.proto=./pkg/proto/txbuilder \
       proto/txbuilder.proto
```