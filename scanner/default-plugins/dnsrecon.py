from scanner.plugins import ServiceScan
from shutil import which

class DnsRecon(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "DnsRecon Default Scan"
		self.slug = 'dnsrecon'
		self.priority = 0
		self.tags = ['default', 'safe', 'dns']

	def configure(self):
		self.match_service_name('^domain')

	def check(self):
		if which('dnsrecon') is None:
			self.error('Программа dnsrecon не найдена. Убедитесь, что он установлен. (В Kali запустите: sudo apt install dnsrecon)')
			return False

	def manual(self, service, plugin_was_run):
		service.add_manual_command('Используйте dnsrecon для автоматического запроса данных с DNS-сервера. Необходимо указать имя целевого домена.', [
			'dnsrecon -n {address} -d <DOMAIN-NAME> 2>&1 | tee {scandir}/{protocol}_{port}_dnsrecon_default_manual.txt'
		])

	async def run(self, service):
		if self.get_global('domain'):
			await service.execute('dnsrecon -n {address} -d ' + self.get_global('domain') + ' 2>&1', outfile='{protocol}_{port}_dnsrecon_default.txt')
		else:
			service.error('В параметрах командной строки не было указано доменное имя (--global.domain). Если вы знаете имя домена, найдите в файле _manual_commands.txt команду dnsrecon.')
