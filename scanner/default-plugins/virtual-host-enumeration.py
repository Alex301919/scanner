from scanner.plugins import ServiceScan
from shutil import which
import os, random, string

class VirtualHost(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Virtual Host Enumeration'
		self.slug = 'vhost-enum'
		self.tags = ['default', 'safe', 'http', 'long']

	def configure(self):
		self.add_option('hostname', help='Имя хоста для использования в качестве базового хоста (например, example.com) для перечисления виртуальных хостов. Обычно: %(default)s')
		self.add_list_option('wordlist', default=['/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt'], help='Словарь для перебора виртуальных хостов. Разделяйте несколько словарей пробелами. Обычно: %(default)s')
		self.add_option('threads', default=10, help='Количество потоков, используемых при переборе хостов. Обычно: %(default)s')
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	async def run(self, service):
		hostnames = []
		if self.get_option('hostname'):
			hostnames.append(self.get_option('hostname'))
		if service.target.type == 'hostname' and service.target.address not in hostnames:
			hostnames.append(service.target.address)
		if self.get_global('domain') and self.get_global('domain') not in hostnames:
			hostnames.append(self.get_global('domain'))

		if len(hostnames) > 0:
			for wordlist in self.get_option('wordlist'):
				name = os.path.splitext(os.path.basename(wordlist))[0]
				for hostname in hostnames:
					_, stdout, _ = await service.execute('curl -sk -o /dev/null -H "Host: ' + ''.join(random.choice(string.ascii_letters) for i in range(20)) + '.' + hostname + '" {http_scheme}://' + hostname + ':{port}/ -w "%{{size_download}}"')

					size = ''.join(await stdout.readlines())

					await service.execute('ffuf -u {http_scheme}://' + hostname + ':{port}/ -t ' + str(self.get_option('threads')) + ' -w ' + wordlist + ' -H "Host: FUZZ.' + hostname + '" -fs ' + size + ' -noninteractive -s | tee "{scandir}/{protocol}_{port}_{http_scheme}_' + hostname + '_vhosts_' + name + '.txt"')
		else:
			service.info('Целью было не имя хоста, и имя хоста не было указано в качестве опции. Пропуск перечисления виртуальных хостов.')
