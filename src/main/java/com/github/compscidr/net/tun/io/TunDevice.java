/*
 * Copyright (c) 2019 Robert Sauter
 * SPDX-License-Identifier: Apache-2.0
 */

package com.github.compscidr.net.tun.io;

import com.sun.jna.LastErrorException;
import com.sun.jna.NativeLong;
import com.github.compscidr.net.tun.io.jna.Darwin;
import com.github.compscidr.net.tun.io.jna.FdAndName;
import com.github.compscidr.net.tun.io.jna.LibC;
import com.github.compscidr.net.tun.io.jna.Linux;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.concurrent.LinkedBlockingDeque;

import jnr.enxio.channels.NativeSelectorProvider;
import jnr.enxio.channels.NativeSocketChannel;

/**
 * Open/create a TUN device on macOS and Linux.
 *
 * <p>While the class supports both Linux and macOS, there are limitations on the latter:</p>
 * <ul>
 *     <li>It is only possible to create new devices (in contrast to opening existing ones).</li>
 *     <li>Names must follow the pattern 'utun[NUMBER]' with 0 being already in use on macOS Sierra and newer.</li>
 * </ul>
 *
 * <p>The basic approach is opening/creating a TUN device with one of the open() methods of this class. After
 * configuring the interface, e.g., with ip/ifconfig, which is not covered by this library, it is possible to read/write
 * IPv4 and IPv6 packets using the appropriate methods. I/O is always performed on packet granularity.</p>
 *
 * <p>The {@link Packet} class is used for reading and can be used for writing (in addition to byte arrays). Apart from
 * the {@link ByteBuffer} representing the packet, it contains a number of utility methods for easier manipulation.</p>
 *
 * <p>On Linux, we recommend creating and configuring the TUN device with the <code>ip</code> command which allows setting
 * permissions so that the application using this library does not need to run with elevated privileges.</p>
 *
 * <p>See <a href="https://github.com/isotes/tun-io-example" target="_top">tun-io-example</a> for a full-fledged
 * example.</p>
 */

public class TunDevice implements AutoCloseable {
	protected final Selector selector;
	volatile private static boolean isOpen = false;
	private LinkedBlockingDeque<ByteBuffer> packetQueue = new LinkedBlockingDeque<ByteBuffer>();
	private static final int DEFAULT_MTU = 2048;
	private static final byte[] IPV4_HEADER_DARWIN = new byte[]{0, 0, 0, 2};  // AF_INET in socket.h
	private static final byte[] IPV6_HEADER_DARWIN = new byte[]{0, 0, 0, 30};  // AF_INET6 in socket.h
	/* package */ final int fd;
	final NativeSocketChannel channel;
	private final String name;
	private final Thread loopThread;
	/* package */ static NativeLong readMtu = new NativeLong(DEFAULT_MTU);
	private static volatile int availableForRead = 0;
	private static ByteBuffer inbuf = ByteBuffer.allocate(readMtu.intValue());

	/* package */ TunDevice(String name, int fd) throws IOException {
		selector = NativeSelectorProvider.getInstance().openSelector();
		this.name = name;
		this.fd = fd;
		channel = new NativeSocketChannel(fd);
		channel.configureBlocking(false);
		channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
		loopThread = new Thread(this::loop);
		loopThread.start();
		inbuf.order(ByteOrder.BIG_ENDIAN);
	}

	/**
	 * Create a new TUN device with the name automatically chosen by the OS. See {@link #open(String)} for more
	 * information.
	 *
	 * @return the new tun device
	 * @throws IOException if one of the system call fails
	 */
	public static TunDevice open() throws IOException {
		TunDevice device = open(null);
		isOpen = true;
		return device;
	}

	/**
	 * Create/open a TUN device name 'utun[NUMBER]'. For compatibility with macOS Sierra and newer, the number should be
	 * greater than 0. See {@link #open(String) } for more information.
	 *
	 * @param number the number
	 * @return the open tun device
	 * @throws IOException if one of the system call fails
	 */
	public static TunDevice open(int number) throws IOException {
		return open("utun" + number);
	}

	/**
	 * Create/open a TUN device with the specified name.
	 *
	 * <p>On Linux, name can be a simple file name (ASCII) of up to 16 characters. </p>
	 *
	 * <p>On macOS, it is only possible to create new devices and the name must be of the form 'utun[N]', with N
	 * being a number starting at 0 (e.g., utun12). However, starting from macOS Sierra, utun0 is always created by the
	 * system and may not be used by other programs. Thus, using a number of 1 or higher is strongly recommended. </p>
	 *
	 * @param name the name of the device or null if the name should be automatically chosen by the OS
	 * @return the open tun device
	 * @throws IOException if one of the system call fails
	 */
	public static TunDevice open(String name) throws IOException {
		try {
			if (System.getProperty("os.name").toLowerCase().contains("mac")) {
				FdAndName fdAndName = Darwin.open(name);
				TunDevice device = new TunDeviceWithHeader(fdAndName.name, fdAndName.fd, IPV4_HEADER_DARWIN, IPV6_HEADER_DARWIN);
				isOpen = true;
				return device;
			} else {
				FdAndName fdAndName = Linux.open(name);
				TunDevice device = new TunDevice(fdAndName.name, fdAndName.fd);
				isOpen = true;
				return device;
			}
		} catch (LastErrorException ex) {
			throw new IOException("Error opening TUN device: " + ex.getMessage(), ex);
		}
	}

	private void try_write() throws IOException {
		if (packetQueue.isEmpty()) {
			channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
			return;
		}
		System.out.println("Waiting for libc write, have queue size: " + packetQueue.size());
		try {
			ByteBuffer packet = packetQueue.take();
			LibC.write(fd, packet, new NativeLong(packet.remaining()));
			channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
		} catch(InterruptedException ex) {
			System.out.println("Interrupted, probably shutting down");
		} catch (LastErrorException ex) {
			System.out.println("Writing to TUN device " + getName() + " failed: " + ex.getMessage() + " " + ex);
		}
		System.out.println("libc write done");
	}

	private void try_read() throws IOException {
		if (availableForRead == 0) {
			System.out.println("Waiting for libc read");
			availableForRead = LibC.read(fd, inbuf, readMtu);
			inbuf.limit(availableForRead);
			System.out.println("libc read done");
			channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
		} else {
			//System.out.println("Waiting for someone to read the existing buffer, not reading now");
			channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
		}
	}

	private static ByteBuffer read_blocking() throws InterruptedException, IOException {
		while (availableForRead == 0) {
			if (!isOpen) {
				throw new IOException("TUN device is closed");
			}
			Thread.sleep(10);
		}
		ByteBuffer packet = ByteBuffer.allocate(availableForRead);
		packet.put(inbuf);
		packet.rewind();
		availableForRead = 0;
		return packet;
	}

	private void loop() {
		while (isOpen) {
			try {
				selector.select();
				for (SelectionKey key : selector.selectedKeys()) {
					if (key.isReadable()) {
						try_read();
					}
					if(key.isWritable()) {
						try_write();
					}
				}
			} catch (IOException e) {
				System.out.println("IO Exception on TUN loop, probably shutting down: " + e);
			}
		}
	}

	public String getName() {
		return name;
	}

	@Override
	public void close() throws IOException, InterruptedException {
		isOpen = false;
		selector.close();
		try {
			System.out.println("Trying to close TUN device");
			LibC.close(fd);
			System.out.println("TUN device closed");
		} catch (LastErrorException ex) {
			throw new IOException("Error closing TUN device: " + ex.getMessage(), ex);
		}
		if (loopThread.isAlive()) {
			System.out.println("Waiting for TUN loop thread to finish");
			loopThread.join();
		}
		System.out.println("TUN Loop thread finished");
	}

	/**
	 * Set the MTU used for the buffers in the read() methods
	 *
	 * @param readMtu the new buffer size when calling the read() methods
	 * @return the TunDevice
	 */
	public void setReadMtu(int readMtu) {
		this.readMtu = new NativeLong(readMtu);
		ByteBuffer.allocate(readMtu);
		availableForRead = 0;
	}

	protected Packet read(int limitIpVersion) throws IOException, InterruptedException {
		try {
			while (isOpen) {
				ByteBuffer recv = read_blocking();
				if (recv.limit() < 4) {
					System.out.println("Didn't get >= 4 bytes, skipping");
					continue;
				}
				int version = Byte.toUnsignedInt(recv.get(0)) >> 4;
				if (version != limitIpVersion && limitIpVersion != 0) {
					System.out.println("Didn't get expected IP version, skipping");
					continue;
				}
				System.out.println("Got a good packet");
				//recv.order(ByteOrder.BIG_ENDIAN);
				return new Packet(recv);
			}
		} catch (LastErrorException ex) {
			throw new IOException("Reading from TUN device " + getName() + " failed: " + ex.getMessage(), ex);
		}
		throw new IOException("TUN device " + getName() + " closed");
	}

	public Packet read() throws IOException, InterruptedException {
		return read(0);
	}

	public Packet readIPv4Packet() throws IOException, InterruptedException {
		return read(4);
	}

	public Packet readIPv6Packet() throws IOException, InterruptedException {
		return read(6);
	}

	public void write(Packet packet) throws InterruptedException {
		write(packet.bytes());
	}

	public void write(ByteBuffer packet) throws InterruptedException {
		packetQueue.put(packet);
	}

	public void write(byte[] packet) throws InterruptedException {
		write(ByteBuffer.wrap(packet));
	}

	public Packet newPacket(int capacity) {
		return new Packet(ByteBuffer.allocate(capacity));
	}

	private static class TunDeviceWithHeader extends TunDevice {
		private final byte[] ipv4Header;
		private final byte[] ipv6Header;
		private final int headerSize;

		/* package */ TunDeviceWithHeader(String name, int fd, byte[] ipv4Header, byte[] ipv6Header) throws IOException {
			super(name, fd);
			this.ipv4Header = ipv4Header;
			this.ipv6Header = ipv6Header;
			this.headerSize = ipv4Header.length;
		}

		@Override
		protected Packet read(int limitIpVersion) throws IOException, InterruptedException {
			try {
				while (isOpen) {
					ByteBuffer recv = read_blocking();
					if (recv.limit() < 4) {
						System.out.println("Didn't get >= 4 bytes, skipping");
						continue;
					}
					int version = Byte.toUnsignedInt(recv.get(headerSize)) >> 4;
					if (version != limitIpVersion && limitIpVersion != 0) {
						System.out.println("Didn't get expected IP version, skipping");
						continue;
					}
					System.out.println("Got a good packet");
					// slice without the header but with the full capacity allowing the later use of the complete buffer
					recv.position(headerSize);
					ByteBuffer packetBuf = recv.slice();
					//packetBuf.order(ByteOrder.BIG_ENDIAN);  // default to network byte order
					packetBuf.limit(recv.limit() - headerSize);
					return new Packet(packetBuf);
				}
			} catch (LastErrorException ex) {
				throw new IOException("Reading from TUN device " + getName() + " failed: " + ex.getMessage(), ex);
			}
			throw new IOException("TUN device " + getName() + " closed");
		}

		@Override
		public void write(ByteBuffer packet) throws InterruptedException {
			byte[] bytes = new byte[headerSize + packet.remaining()];
			byte[] header = Byte.toUnsignedInt(packet.get(0)) >> 4 == 6 ? ipv6Header : ipv4Header;
			System.arraycopy(header, 0, bytes, 0, header.length);
			packet.slice().get(bytes, headerSize, packet.remaining());
			super.write(bytes);
		}

		@Override
		public void write(byte[] packet) throws InterruptedException {
			byte[] bytes = new byte[headerSize + packet.length];
			byte[] header = Byte.toUnsignedInt(packet[0]) >> 4 == 6 ? ipv6Header : ipv4Header;
			System.arraycopy(header, 0, bytes, 0, header.length);
			System.arraycopy(packet, 0, bytes, headerSize, packet.length);
			super.write(bytes);
		}

	}
}
