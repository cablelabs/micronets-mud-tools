DOCKER_REGISTRY := community.cablelabs.com:4567
DOCKER_IMAGE_PATH := micronets-docker/micronets-mud-manager 

docker-build:
	docker build -t $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_PATH) .

docker-push: docker-build
	docker login $(DOCKER_REGISTRY)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_PATH)

docker-pull:
	docker pull $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_PATH)

docker-run:
	docker run -d --network host --restart unless-stopped \
		--name micronets-mud-manager-service \
		-v /var/cache/micronets-mud:/mud-cache-dir \
		$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_PATH)

docker-kill:
	docker kill micronets-mud-manager-service

docker-rm: docker-kill
    docker rm micronets-mud-manager-service
