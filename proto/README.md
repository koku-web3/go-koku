
生成`signer`项目 .pd.go 文件
``` bash
protoc --go_out=. \
       --go_opt=Mproto/signer.proto=./internal/signer/grpc \
       --go-grpc_out=. \
       --go-grpc_opt=Mproto/signer.proto=./internal/signer/grpc \
       proto/signer.proto
```

生成`coordinator`项目 .pd.go 文件
``` bash
protoc --go_out=. \
       --go_opt=Mproto/coordinator.proto=./internal/coordinator/grpc \
       --go-grpc_out=. \
       --go-grpc_opt=Mproto/coordinator.proto=./internal/coordinator/grpc \
       proto/coordinator.proto
```