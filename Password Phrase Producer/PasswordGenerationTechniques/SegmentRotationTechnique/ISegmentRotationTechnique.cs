namespace Password_Phrase_Producer.PasswordGenerationTechniques.SegmentRotationTechnique
{
    public interface ISegmentRotationTechnique
    {
        string ShuffleSegments(string input, int segmentLength);
    }
}
