namespace Scavanger.MemoryModule
{
    internal unsafe struct HCoustomMudule
    {
        public void* Value { get; set; }

        public HCoustomMudule(void* ptr) => Value = ptr;

        public static implicit operator HCoustomMudule(void* value) => new HCoustomMudule(value);

        public static implicit operator void* (HCoustomMudule value) => value.Value;
    }
}
