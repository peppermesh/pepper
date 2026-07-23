// SPDX-License-Identifier: Apache-2.0

use crate::{
    PageReference, SqliteBlockStore, SqliteError, SqliteFormatLimits,
    format::{
        PageTableChild, PageTableNode, PageTableNodeKind, decode_canonical, encode_canonical,
    },
};
use pepper_types::{CODEC_SQLITE_PAGE_TABLE, Cid};
use std::collections::HashSet;
use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageMutation {
    Put(PageReference),
    Delete(u32),
}

impl PageMutation {
    fn page_number(&self) -> u32 {
        match self {
            Self::Put(page) => page.page_number,
            Self::Delete(page_number) => *page_number,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageTableUpdate {
    pub root: Cid,
    /// New page-table blocks in deterministic leaf-to-root order.
    pub written_nodes: Vec<Cid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageTableValidation {
    pub node_count: u64,
    pub page_count: u32,
    pub node_cids: Vec<Cid>,
    pub page_pack_roots: Vec<Cid>,
}

/// Memory-bounded canonical builder for already sorted page references. It
/// retains only one leaf's pages plus the resulting leaf CIDs.
pub struct PageTableBulkBuilder<'a, S: SqliteBlockStore + ?Sized> {
    table: PageTable,
    store: &'a S,
    page_size: u32,
    prior_page: Option<u32>,
    current_prefix: Option<[u8; 3]>,
    current_pages: Vec<PageReference>,
    leaves: Vec<([u8; 3], Cid)>,
    written_nodes: Vec<Cid>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PageTable {
    pub limits: SqliteFormatLimits,
}

impl PageTable {
    pub fn bulk_builder<'a, S: SqliteBlockStore + ?Sized>(
        &self,
        store: &'a S,
        page_size: u32,
    ) -> Result<PageTableBulkBuilder<'a, S>, SqliteError> {
        if page_size < 512 || page_size > self.limits.max_page_size || !page_size.is_power_of_two()
        {
            return Err(SqliteError::Invalid("invalid page size".into()));
        }
        Ok(PageTableBulkBuilder {
            table: *self,
            store,
            page_size,
            prior_page: None,
            current_prefix: None,
            current_pages: Vec::with_capacity(256),
            leaves: Vec::new(),
            written_nodes: Vec::new(),
        })
    }

    pub async fn empty_root<S: SqliteBlockStore + ?Sized>(
        &self,
        store: &S,
    ) -> Result<Cid, SqliteError> {
        self.put_node(store, &PageTableNode::empty_root()).await
    }

    pub async fn get<S: SqliteBlockStore + ?Sized>(
        &self,
        store: &S,
        root: &Cid,
        page_number: u32,
    ) -> Result<Option<PageReference>, SqliteError> {
        self.validate_page_number(page_number)?;
        let bytes = page_number.to_be_bytes();
        let mut cid = root.clone();
        for level in 0..3u8 {
            let node = self.get_node(store, &cid).await?;
            self.expect_node(
                &node,
                PageTableNodeKind::Internal,
                level,
                &bytes[..level as usize],
            )?;
            let Some(child) = node
                .children
                .iter()
                .find(|child| child.edge == bytes[level as usize])
            else {
                return Ok(None);
            };
            cid = child.cid.clone();
        }
        let leaf = self.get_node(store, &cid).await?;
        self.expect_node(&leaf, PageTableNodeKind::Leaf, 3, &bytes[..3])?;
        Ok(leaf
            .pages
            .binary_search_by_key(&page_number, |page| page.page_number)
            .ok()
            .map(|index| leaf.pages[index].clone()))
    }

    /// Resolve a bounded set of pages while preserving caller order.
    pub async fn get_many<S: SqliteBlockStore + ?Sized>(
        &self,
        store: &S,
        root: &Cid,
        page_numbers: &[u32],
    ) -> Result<Vec<Option<PageReference>>, SqliteError> {
        if page_numbers.len() > 256 {
            return Err(SqliteError::Limit("page lookup batch exceeds 256".into()));
        }
        let mut result = Vec::with_capacity(page_numbers.len());
        for page_number in page_numbers {
            result.push(self.get(store, root, *page_number).await?);
        }
        Ok(result)
    }

    /// Traverse and validate the complete fixed-depth tree. When
    /// `require_dense` is true, the tree must contain pages 1..=page_count.
    pub async fn validate_complete<S: SqliteBlockStore + ?Sized>(
        &self,
        store: &S,
        root: &Cid,
        page_size: u32,
        expected_page_count: u32,
        require_dense: bool,
    ) -> Result<PageTableValidation, SqliteError> {
        self.normalize(page_size, Vec::new())?;
        if expected_page_count > self.limits.max_page_count {
            return Err(SqliteError::Limit("page-table page count".into()));
        }
        let mut pending = vec![(root.clone(), 0u8, Vec::<u8>::new())];
        let mut visited = HashSet::new();
        let mut node_count = 0u64;
        let mut page_count = 0u32;
        let mut prior_page = None;
        let mut node_cids = Vec::new();
        let mut page_pack_roots = HashSet::new();
        while let Some((cid, level, prefix)) = pending.pop() {
            if !visited.insert(cid.clone()) {
                return Err(SqliteError::Invalid(
                    "page-table node is linked more than once or forms a cycle".into(),
                ));
            }
            node_count = node_count
                .checked_add(1)
                .ok_or_else(|| SqliteError::Limit("page-table node count".into()))?;
            node_cids.push(cid.clone());
            let node = self.get_node(store, &cid).await?;
            let kind = if level == 3 {
                PageTableNodeKind::Leaf
            } else {
                PageTableNodeKind::Internal
            };
            self.expect_node(&node, kind, level, &prefix)?;
            if level == 3 {
                for page in &node.pages {
                    page.validate(page_size, self.limits)?;
                    page_pack_roots.insert(page.pack_cid.clone());
                    if prior_page.is_some_and(|prior| prior >= page.page_number) {
                        return Err(SqliteError::Invalid(
                            "page-table traversal is not strictly ordered".into(),
                        ));
                    }
                    if require_dense && page.page_number != page_count.saturating_add(1) {
                        return Err(SqliteError::Invalid("page table is sparse".into()));
                    }
                    prior_page = Some(page.page_number);
                    page_count = page_count
                        .checked_add(1)
                        .ok_or_else(|| SqliteError::Limit("page-table page count".into()))?;
                }
            } else {
                // Reverse push preserves ascending edge order when popping.
                for child in node.children.iter().rev() {
                    let mut child_prefix = prefix.clone();
                    child_prefix.push(child.edge);
                    pending.push((child.cid.clone(), level + 1, child_prefix));
                }
            }
        }
        if page_count != expected_page_count {
            return Err(SqliteError::Invalid(format!(
                "page table has {page_count} pages, expected {expected_page_count}"
            )));
        }
        let mut page_pack_roots = page_pack_roots.into_iter().collect::<Vec<_>>();
        page_pack_roots.sort_by_key(ToString::to_string);
        Ok(PageTableValidation {
            node_count,
            page_count,
            node_cids,
            page_pack_roots,
        })
    }

    /// Apply a transaction-sized mutation set with structural sharing. Only
    /// affected leaves and their three ancestor levels are rewritten.
    pub async fn apply<S: SqliteBlockStore + ?Sized>(
        &self,
        store: &S,
        root: &Cid,
        page_size: u32,
        mutations: Vec<PageMutation>,
    ) -> Result<PageTableUpdate, SqliteError> {
        let root_node = self.get_node(store, root).await?;
        self.expect_node(&root_node, PageTableNodeKind::Internal, 0, &[])?;
        let normalized = self.normalize(page_size, mutations)?;
        if normalized.is_empty() {
            return Ok(PageTableUpdate {
                root: root.clone(),
                written_nodes: Vec::new(),
            });
        }

        let mut leaves = BTreeMap::<[u8; 3], PageTableNode>::new();
        let mut level_two = BTreeMap::<[u8; 2], PageTableNode>::new();
        let mut level_one = BTreeMap::<[u8; 1], PageTableNode>::new();

        for mutation in normalized.values() {
            let bytes = mutation.page_number().to_be_bytes();
            let p1 = [bytes[0]];
            let p2 = [bytes[0], bytes[1]];
            let p3 = [bytes[0], bytes[1], bytes[2]];
            if let Entry::Vacant(entry) = level_one.entry(p1) {
                let node = self
                    .load_child_internal(store, &root_node, bytes[0], 1, &p1)
                    .await?;
                entry.insert(node);
            }
            if let Entry::Vacant(entry) = level_two.entry(p2) {
                let parent = level_one.get(&p1).expect("loaded level one");
                let node = self
                    .load_child_internal(store, parent, bytes[1], 2, &p2)
                    .await?;
                entry.insert(node);
            }
            if let Entry::Vacant(entry) = leaves.entry(p3) {
                let parent = level_two.get(&p2).expect("loaded level two");
                let node = self.load_leaf(store, parent, bytes[2], p3).await?;
                entry.insert(node);
            }
        }

        for mutation in normalized.into_values() {
            let bytes = mutation.page_number().to_be_bytes();
            let leaf = leaves
                .get_mut(&[bytes[0], bytes[1], bytes[2]])
                .expect("loaded leaf");
            match mutation {
                PageMutation::Put(page) => match leaf
                    .pages
                    .binary_search_by_key(&page.page_number, |item| item.page_number)
                {
                    Ok(index) => leaf.pages[index] = page,
                    Err(index) => leaf.pages.insert(index, page),
                },
                PageMutation::Delete(page_number) => {
                    if let Ok(index) = leaf
                        .pages
                        .binary_search_by_key(&page_number, |item| item.page_number)
                    {
                        leaf.pages.remove(index);
                    }
                }
            }
        }

        let mut written_nodes = Vec::new();
        for (prefix, leaf) in &leaves {
            let parent = level_two
                .get_mut(&[prefix[0], prefix[1]])
                .expect("loaded parent");
            let cid = if leaf.pages.is_empty() {
                None
            } else {
                let cid = self.put_node(store, leaf).await?;
                written_nodes.push(cid.clone());
                Some(cid)
            };
            set_child(&mut parent.children, prefix[2], cid);
        }

        let mut changed_level_two = BTreeMap::new();
        for prefix in leaves.keys() {
            changed_level_two.insert([prefix[0], prefix[1]], ());
        }
        for prefix in changed_level_two.keys() {
            let node = level_two.get(prefix).expect("loaded level two");
            let parent = level_one.get_mut(&[prefix[0]]).expect("loaded parent");
            let cid = if node.children.is_empty() {
                None
            } else {
                let cid = self.put_node(store, node).await?;
                written_nodes.push(cid.clone());
                Some(cid)
            };
            set_child(&mut parent.children, prefix[1], cid);
        }

        let mut new_root = root_node;
        let mut changed_level_one = BTreeSet::new();
        for prefix in changed_level_two.keys() {
            changed_level_one.insert([prefix[0]]);
        }
        for prefix in changed_level_one {
            let node = level_one.get(&prefix).expect("loaded level one");
            let cid = if node.children.is_empty() {
                None
            } else {
                let cid = self.put_node(store, node).await?;
                written_nodes.push(cid.clone());
                Some(cid)
            };
            set_child(&mut new_root.children, prefix[0], cid);
        }
        let new_root_cid = self.put_node(store, &new_root).await?;
        written_nodes.push(new_root_cid.clone());
        Ok(PageTableUpdate {
            root: new_root_cid,
            written_nodes,
        })
    }

    /// Drop every page above `new_page_count` by pruning whole radix subtrees
    /// and rewriting only the surviving boundary path.
    pub async fn truncate<S: SqliteBlockStore + ?Sized>(
        &self,
        store: &S,
        root: &Cid,
        page_size: u32,
        old_page_count: u32,
        new_page_count: u32,
    ) -> Result<PageTableUpdate, SqliteError> {
        // Reject invalid input before performing any immutable writes.
        self.normalize(page_size, Vec::new())?;
        if new_page_count > old_page_count || old_page_count > self.limits.max_page_count {
            return Err(SqliteError::Invalid("invalid page-table truncation".into()));
        }
        if new_page_count == old_page_count {
            return Ok(PageTableUpdate {
                root: root.clone(),
                written_nodes: Vec::new(),
            });
        }
        if new_page_count == 0 {
            let empty = self.empty_root(store).await?;
            return Ok(PageTableUpdate {
                root: empty.clone(),
                written_nodes: vec![empty],
            });
        }
        let boundary = new_page_count.to_be_bytes();
        let mut root_node = self.get_node(store, root).await?;
        self.expect_node(&root_node, PageTableNodeKind::Internal, 0, &[])?;
        root_node.children.retain(|child| child.edge <= boundary[0]);
        let Some(level_one_cid) = root_node
            .children
            .iter()
            .find(|child| child.edge == boundary[0])
            .map(|child| child.cid.clone())
        else {
            let new_root = self.put_node(store, &root_node).await?;
            return Ok(PageTableUpdate {
                root: new_root.clone(),
                written_nodes: vec![new_root],
            });
        };
        let mut level_one = self.get_node(store, &level_one_cid).await?;
        self.expect_node(&level_one, PageTableNodeKind::Internal, 1, &boundary[..1])?;
        level_one.children.retain(|child| child.edge <= boundary[1]);
        let mut written_nodes = Vec::new();
        if let Some(level_two_cid) = level_one
            .children
            .iter()
            .find(|child| child.edge == boundary[1])
            .map(|child| child.cid.clone())
        {
            let mut level_two = self.get_node(store, &level_two_cid).await?;
            self.expect_node(&level_two, PageTableNodeKind::Internal, 2, &boundary[..2])?;
            level_two.children.retain(|child| child.edge <= boundary[2]);
            if let Some(leaf_cid) = level_two
                .children
                .iter()
                .find(|child| child.edge == boundary[2])
                .map(|child| child.cid.clone())
            {
                let mut leaf = self.get_node(store, &leaf_cid).await?;
                self.expect_node(&leaf, PageTableNodeKind::Leaf, 3, &boundary[..3])?;
                leaf.pages.retain(|page| page.page_number <= new_page_count);
                let cid = if leaf.pages.is_empty() {
                    None
                } else {
                    let cid = self.put_node(store, &leaf).await?;
                    written_nodes.push(cid.clone());
                    Some(cid)
                };
                set_child(&mut level_two.children, boundary[2], cid);
            }
            let cid = if level_two.children.is_empty() {
                None
            } else {
                let cid = self.put_node(store, &level_two).await?;
                written_nodes.push(cid.clone());
                Some(cid)
            };
            set_child(&mut level_one.children, boundary[1], cid);
        }
        let cid = if level_one.children.is_empty() {
            None
        } else {
            let cid = self.put_node(store, &level_one).await?;
            written_nodes.push(cid.clone());
            Some(cid)
        };
        set_child(&mut root_node.children, boundary[0], cid);
        let new_root = self.put_node(store, &root_node).await?;
        written_nodes.push(new_root.clone());
        Ok(PageTableUpdate {
            root: new_root,
            written_nodes,
        })
    }

    fn normalize(
        &self,
        page_size: u32,
        mutations: Vec<PageMutation>,
    ) -> Result<BTreeMap<u32, PageMutation>, SqliteError> {
        if page_size < 512 || page_size > self.limits.max_page_size || !page_size.is_power_of_two()
        {
            return Err(SqliteError::Invalid("invalid page size".into()));
        }
        let mut out = BTreeMap::new();
        for mutation in mutations {
            let number = mutation.page_number();
            self.validate_page_number(number)?;
            if let PageMutation::Put(page) = &mutation {
                page.validate(page_size, self.limits)?;
            }
            out.insert(number, mutation);
        }
        Ok(out)
    }

    fn validate_page_number(&self, page_number: u32) -> Result<(), SqliteError> {
        if page_number == 0 || page_number > self.limits.max_page_count {
            return Err(SqliteError::Invalid(format!(
                "page number {page_number} is outside configured limits"
            )));
        }
        Ok(())
    }

    async fn load_child_internal<S: SqliteBlockStore + ?Sized>(
        &self,
        store: &S,
        parent: &PageTableNode,
        edge: u8,
        level: u8,
        prefix: &[u8],
    ) -> Result<PageTableNode, SqliteError> {
        match parent.children.iter().find(|child| child.edge == edge) {
            Some(child) => {
                let node = self.get_node(store, &child.cid).await?;
                self.expect_node(&node, PageTableNodeKind::Internal, level, prefix)?;
                Ok(node)
            }
            None => Ok(PageTableNode::internal(level, prefix.to_vec(), Vec::new())),
        }
    }

    async fn load_leaf<S: SqliteBlockStore + ?Sized>(
        &self,
        store: &S,
        parent: &PageTableNode,
        edge: u8,
        prefix: [u8; 3],
    ) -> Result<PageTableNode, SqliteError> {
        match parent.children.iter().find(|child| child.edge == edge) {
            Some(child) => {
                let node = self.get_node(store, &child.cid).await?;
                self.expect_node(&node, PageTableNodeKind::Leaf, 3, &prefix)?;
                Ok(node)
            }
            None => Ok(PageTableNode::leaf(prefix, Vec::new())),
        }
    }

    pub(crate) fn expect_node(
        &self,
        node: &PageTableNode,
        kind: PageTableNodeKind,
        level: u8,
        prefix: &[u8],
    ) -> Result<(), SqliteError> {
        node.validate(self.limits)?;
        let expected = PageTableNode::internal(level, prefix.to_vec(), Vec::new()).prefix;
        if node.kind != kind || node.level != level || node.prefix != expected {
            return Err(SqliteError::Invalid(
                "page-table child is at the wrong path".into(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn get_node<S: SqliteBlockStore + ?Sized>(
        &self,
        store: &S,
        cid: &Cid,
    ) -> Result<PageTableNode, SqliteError> {
        if cid.codec != CODEC_SQLITE_PAGE_TABLE {
            return Err(SqliteError::Invalid("unexpected page-table codec".into()));
        }
        let payload = store.get(cid).await.map_err(SqliteError::Storage)?;
        if !cid.verify(&payload) {
            return Err(SqliteError::Storage(format!(
                "page-table block {cid} failed hash verification"
            )));
        }
        let node: PageTableNode =
            decode_canonical(&payload, self.limits.max_page_table_node_bytes)?;
        node.validate(self.limits)?;
        Ok(node)
    }

    pub(crate) async fn put_node<S: SqliteBlockStore + ?Sized>(
        &self,
        store: &S,
        node: &PageTableNode,
    ) -> Result<Cid, SqliteError> {
        node.validate(self.limits)?;
        let payload = encode_canonical(node, self.limits.max_page_table_node_bytes)?;
        let expected = Cid::new(CODEC_SQLITE_PAGE_TABLE, &payload);
        let actual = store
            .put(CODEC_SQLITE_PAGE_TABLE, payload)
            .await
            .map_err(SqliteError::Storage)?;
        if actual != expected {
            return Err(SqliteError::Storage(format!(
                "store returned {actual}, expected {expected}"
            )));
        }
        Ok(actual)
    }
}

impl<'a, S: SqliteBlockStore + ?Sized> PageTableBulkBuilder<'a, S> {
    pub async fn push(&mut self, page: PageReference) -> Result<(), SqliteError> {
        page.validate(self.page_size, self.table.limits)?;
        if self
            .prior_page
            .is_some_and(|prior| prior >= page.page_number)
        {
            return Err(SqliteError::Invalid(
                "bulk page references must be strictly sorted".into(),
            ));
        }
        let bytes = page.page_number.to_be_bytes();
        let prefix = [bytes[0], bytes[1], bytes[2]];
        if self.current_prefix.is_some_and(|current| current != prefix) {
            self.flush_leaf().await?;
        }
        self.current_prefix = Some(prefix);
        self.prior_page = Some(page.page_number);
        self.current_pages.push(page);
        Ok(())
    }

    pub async fn finish(mut self) -> Result<PageTableUpdate, SqliteError> {
        self.flush_leaf().await?;
        let mut level_two = Vec::<([u8; 2], Cid)>::new();
        let mut start = 0;
        while start < self.leaves.len() {
            let prefix = [self.leaves[start].0[0], self.leaves[start].0[1]];
            let mut end = start + 1;
            while end < self.leaves.len() && self.leaves[end].0[..2] == prefix {
                end += 1;
            }
            let group = &self.leaves[start..end];
            let children = group
                .iter()
                .map(|(leaf_prefix, cid)| PageTableChild {
                    edge: leaf_prefix[2],
                    cid: cid.clone(),
                })
                .collect();
            let cid = self
                .table
                .put_node(
                    self.store,
                    &PageTableNode::internal(2, prefix.to_vec(), children),
                )
                .await?;
            self.written_nodes.push(cid.clone());
            level_two.push((prefix, cid));
            start = end;
        }
        let mut level_one = Vec::<([u8; 1], Cid)>::new();
        let mut start = 0;
        while start < level_two.len() {
            let prefix = [level_two[start].0[0]];
            let mut end = start + 1;
            while end < level_two.len() && level_two[end].0[0] == prefix[0] {
                end += 1;
            }
            let group = &level_two[start..end];
            let children = group
                .iter()
                .map(|(child_prefix, cid)| PageTableChild {
                    edge: child_prefix[1],
                    cid: cid.clone(),
                })
                .collect();
            let cid = self
                .table
                .put_node(
                    self.store,
                    &PageTableNode::internal(1, prefix.to_vec(), children),
                )
                .await?;
            self.written_nodes.push(cid.clone());
            level_one.push((prefix, cid));
            start = end;
        }
        let root = PageTableNode::internal(
            0,
            Vec::new(),
            level_one
                .into_iter()
                .map(|(prefix, cid)| PageTableChild {
                    edge: prefix[0],
                    cid,
                })
                .collect(),
        );
        let root = self.table.put_node(self.store, &root).await?;
        self.written_nodes.push(root.clone());
        Ok(PageTableUpdate {
            root,
            written_nodes: self.written_nodes,
        })
    }

    async fn flush_leaf(&mut self) -> Result<(), SqliteError> {
        let Some(prefix) = self.current_prefix.take() else {
            return Ok(());
        };
        let pages = std::mem::replace(&mut self.current_pages, Vec::with_capacity(256));
        let cid = self
            .table
            .put_node(self.store, &PageTableNode::leaf(prefix, pages))
            .await?;
        self.written_nodes.push(cid.clone());
        self.leaves.push((prefix, cid));
        Ok(())
    }
}

fn set_child(children: &mut Vec<PageTableChild>, edge: u8, cid: Option<Cid>) {
    match children.binary_search_by_key(&edge, |child| child.edge) {
        Ok(index) => match cid {
            Some(cid) => children[index].cid = cid,
            None => {
                children.remove(index);
            }
        },
        Err(index) => {
            if let Some(cid) = cid {
                children.insert(index, PageTableChild { edge, cid });
            }
        }
    }
}
