.PHONY: supervisor
supervisor:
	apt-get install supervisor

.PHONY: deploy
deploy:
	cp ./http_agent.supervisor.conf /etc/supervisor/conf.d/http_agent.supervisor.conf
	sed -i 's:%(ENV_TND_HTTP_AGENT_PATH)s:'`pwd`':g' /etc/supervisor/conf.d/http_agent.supervisor.conf
	supervisorctl reload all

	cp ./http_agent.nginx.site /usr/local/nginx/conf/sites/
	service nginx reload
