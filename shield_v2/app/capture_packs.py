PACKS={
 "general":{"label":"General evidence","required_points":[]},
 "prework":{"label":"Pre-work condition","required_points":["overview","detail"]},
 "progress":{"label":"Progress documentation","required_points":["overview"]},
 "closeout":{"label":"Close-out","required_points":["completed_work","surrounding_condition"]},
}
def get_pack(pack_id): return PACKS.get(pack_id)
