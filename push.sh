mvn clean package
uuid=$(uuidgen)
#dev
aws ecr get-login-password --profile wit-devel  --region eu-west-1 | docker login --username AWS --password-stdin 978780646398.dkr.ecr.eu-west-1.amazonaws.com
tag=978780646398.dkr.ecr.eu-west-1.amazonaws.com/keycloak-magic-link-spi:"$uuid"
#prod
#aws ecr get-login-password --profile wit-prod  --region eu-west-1 | docker login --username AWS --password-stdin 914711735971.dkr.ecr.eu-west-1.amazonaws.com
#tag=914711735971.dkr.ecr.eu-west-1.amazonaws.com/keycloak-magic-link-spi:"$uuid"
docker build --platform linux/amd64 -t keycloak-magic-link-spi .
docker tag keycloak-magic-link-spi "$tag"
docker push "$tag"
echo "$tag"