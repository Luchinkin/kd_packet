static uint32_t kd_calculate_checksum( const void* buffer, uint32_t length ) noexcept
{
	auto buf = reinterpret_cast<const char*>( buffer );
	uint32_t result = 0;

	while ( length-- > 0 )
		result += (uint32_t)*buf++;

	return result;
}
enum kd_packet_type : uint16_t
{
	unk = 0,
	io = 3u
};
#pragma pack( push, 1 )

struct kd_packet_header
{
	static kd_packet_header build( uint32_t buf_size ) noexcept
	{
		kd_packet_header result{};
		result.pad1 = 0x600003230;
		result.length = buf_size;
		result.pad2 = 0;
		return result;
	}

	PUCHAR get() noexcept { return reinterpret_cast<PUCHAR>( this ); }

	uint64_t pad1 = 0;
	uint32_t length = 0;
	uint32_t pad2 = 0;
};

struct kd_packet
{
	static constexpr auto leader = 0x30303030;
	static constexpr auto trail = 0xAA;
	static constexpr auto packet_id_expected = 0x80800800;

	static std::pair<kd_packet, kd_packet_header> build_io( const char* buffer ) noexcept
	{
		const auto length = [&]()
		{
			auto tmp = buffer;
			uint32_t result = 0u;
			while ( *tmp )
			{
				result++;
				tmp++;
			}
			return result;
		}();
		const auto checksum = kd_calculate_checksum( buffer, length );
		kd_packet packet{};

		const auto header = kd_packet_header::build( length );
		const auto header_checksum = kd_calculate_checksum( &header, sizeof( kd_packet_header ) );

		packet.packet_leader = leader;
		packet.packet_type = kd_packet_type::io;
		packet.byte_count = static_cast<uint16_t>( sizeof( kd_packet_header ) + length );
		packet.checksum = header_checksum + checksum;
		packet.packet_id = packet_id_expected;

		return { packet, header };
	}

	PUCHAR get() noexcept { return reinterpret_cast<PUCHAR>( this ); }

	uint32_t packet_leader = 0;
	kd_packet_type packet_type = kd_packet_type::unk;
	uint16_t byte_count = 0;
	uint32_t packet_id = 0;
	uint32_t checksum = 0;
};

#pragma pack( pop )
static_assert( sizeof( kd_packet ) == 16 );
static_assert( sizeof( kd_packet_header ) == 16 );
