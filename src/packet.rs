use anyhow::{Context, Result, anyhow, bail};

const MAGIC: &[u8; 8] = b"EXEPACK\x02";
const FOOTER_LEN: usize = 8 + 4 + 8;

pub(super) fn build(items: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
	let mut data = Vec::new();
	let mut index = Vec::new();
	for (name, stored) in items {
		let length = u16::try_from(name.len()).context("an item name is too long")?;
		let offset = u64::try_from(data.len())?;
		index.extend_from_slice(&length.to_le_bytes());
		index.extend_from_slice(name.as_bytes());
		index.extend_from_slice(&offset.to_le_bytes());
		index.extend_from_slice(&u64::try_from(stored.len())?.to_le_bytes());
		data.extend_from_slice(stored);
	}
	let index_offset = u64::try_from(data.len())?;
	data.extend_from_slice(&index);
	data.extend_from_slice(MAGIC);
	data.extend_from_slice(&u32::try_from(items.len())?.to_le_bytes());
	data.extend_from_slice(&index_offset.to_le_bytes());
	Ok(data)
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, len: usize) -> Result<&'a [u8]> {
	let end = at.checked_add(len).context("item index overflows")?;
	let part = bytes.get(*at..end).context("item index is truncated")?;
	*at = end;
	Ok(part)
}

pub(super) fn find<'a>(packet: &'a [u8], name: &str) -> Result<&'a [u8]> {
	let footer_start = packet
		.len()
		.checked_sub(FOOTER_LEN)
		.context("item package is truncated")?;
	let footer = &packet[footer_start..];
	if &footer[..8] != MAGIC {
		bail!("item package has an unknown format");
	}
	let count = u32::from_le_bytes(footer[8..12].try_into()?);
	let index_start = usize::try_from(u64::from_le_bytes(footer[12..20].try_into()?))?;
	let index = packet
		.get(index_start..footer_start)
		.context("item index is outside the package")?;
	let mut at = 0;
	for _ in 0..count {
		let name_len = usize::from(u16::from_le_bytes(take(index, &mut at, 2)?.try_into()?));
		let key = take(index, &mut at, name_len)?;
		let fields = take(index, &mut at, 16)?;
		if key == name.as_bytes() {
			let offset = usize::try_from(u64::from_le_bytes(fields[..8].try_into()?))?;
			let len = usize::try_from(u64::from_le_bytes(fields[8..].try_into()?))?;
			let end = offset.checked_add(len).context("item range overflows")?;
			return packet
				.get(offset..end)
				.filter(|_| end <= index_start)
				.ok_or_else(|| anyhow!("item data is outside the package"));
		}
	}
	bail!("no item is embedded as {name:?}")
}
